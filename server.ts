import express from "express";
import path from "path";
import fs from "fs";
import { GoogleGenAI } from "@google/genai";
import dotenv from "dotenv";
import { getAuthenticatedUser as verifyFirebaseToken, firestoreDb, generateToken, firebaseAuthSignUp, firebaseAuthSignIn, hashPassword } from "./server-firebase";
import Razorpay from "razorpay";
import crypto from "crypto";
import createOrderHandler from "./api/create-order";
import verifyPaymentHandler from "./api/verify-payment";
import razorpayOrderHandler from "./api/razorpay/order";
import razorpayVerifyHandler from "./api/razorpay/verify";
import ocrHandler from "./api/ocr";

dotenv.config();

const app = express();
const PORT = 3000;

// Enable CORS middleware
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// Increase payloads limit to handle base64 image uploads
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Helper to authenticate user and auto-create Firestore profile if they are new
async function getAuthenticatedUser(req: any) {
  console.log("server: getAuthenticatedUser: Started verification for headers:", req.headers.authorization ? req.headers.authorization.substring(0, 30) + "..." : "none");
  const authUser = await verifyFirebaseToken(req);
  if (!authUser) {
    console.log("server: getAuthenticatedUser: verifyFirebaseToken returned null authUser");
    return null;
  }
  if (!authUser.email) {
    console.log("server: getAuthenticatedUser: authUser has no email", authUser);
    return null;
  }
  const email = authUser.email;
  console.log("server: getAuthenticatedUser: Verified user email:", email);
  
  // Get the token from authorization header to use in Firestore REST calls
  const authHeader = req.headers.authorization || req.headers.Authorization;
  const idToken = authHeader && authHeader.toLowerCase().startsWith("bearer ") ? authHeader.substring(7).trim() : undefined;

  let profile = await firestoreDb.getUser(email, idToken);
  if (!profile) {
    console.log("server: getAuthenticatedUser: No profile found for email, creating a new one...");
    profile = await firestoreDb.createUser(email, authUser.name || email.split('@')[0], 90, idToken);
  } else {
    console.log("server: getAuthenticatedUser: Loaded profile from db:", profile.username);
  }
  return { ...profile, idToken };
}

// Auth API - Get Current Profile (Me)
app.get("/api/auth/me", async (req, res) => {
  try {
    const profile = await getAuthenticatedUser(req);
    if (!profile) {
      return res.status(401).json({ error: "Unauthorized", message: "Invalid or expired session token." });
    }
    res.json({
      success: true,
      user: {
        username: profile.username,
        email: profile.email,
        credits: profile.credits,
        promptHistory: profile.promptHistory || []
      }
    });
  } catch (error: any) {
    console.error("Auth Me check failed in Express:", error);
    res.status(500).json({ error: "Failed to get profile" });
  }
});

// Auth API - Custom Native Signup (immune to Brave/Adblockers & iframe storage blocks)
app.post("/api/auth/custom-signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: "Username, email, and password are required." });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters long." });
    }
    
    // Try to register in Firebase Auth first
    let idToken: string;
    try {
      const authResult = await firebaseAuthSignUp(email, password);
      if (!authResult) {
        throw new Error("Failed to register in Firebase Auth.");
      }
      idToken = authResult.idToken;
    } catch (err: any) {
      if (err.message && (err.message.includes("EMAIL_EXISTS") || err.message.includes("already registered") || err.message.includes("already in use"))) {
        return res.status(400).json({ error: "Email address is already registered." });
      }
      throw err;
    }

    // Register in Firestore using the idToken
    const newUser = await firestoreDb.createUserWithPassword(email, username, password, 90, idToken);

    res.json({
      success: true,
      token: idToken,
      user: newUser
    });
  } catch (error: any) {
    console.error("Custom signup failed:", error);
    res.status(500).json({ error: error.message || "Failed to register account." });
  }
});

// Auth API - Custom Native Login (immune to Brave/Adblockers & iframe storage blocks)
app.post("/api/auth/custom-login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required." });
    }

    let idToken: string | null = null;
    let user: any = null;

    try {
      // 1. Try standard Firebase Auth Login
      const authResult = await firebaseAuthSignIn(email, password);
      if (authResult) {
        idToken = authResult.idToken;
        user = await firestoreDb.getUser(email, idToken);
      }
    } catch (authErr: any) {
      // 2. If user not found in Firebase Auth, check if they exist in Firestore legacy database
      const errMessage = authErr.message || "";
      if (errMessage.includes("EMAIL_NOT_FOUND") || errMessage.includes("USER_NOT_FOUND")) {
        const legacyUser = await firestoreDb.verifyUserPassword(email, password);
        if (legacyUser) {
          // Password is correct! Migrate them to Firebase Auth dynamically
          try {
            const signupResult = await firebaseAuthSignUp(email, password);
            if (signupResult) {
              idToken = signupResult.idToken;
              // Save the updated profile to Firestore with the idToken
              await firestoreDb.setUser(email, {
                username: legacyUser.username,
                email: legacyUser.email,
                credits: legacyUser.credits,
                promptHistory: legacyUser.promptHistory || [],
                passwordHash: hashPassword(password)
              }, idToken);
              user = legacyUser;
            }
          } catch (migrateErr) {
            console.error("Failed to migrate legacy user:", migrateErr);
          }
        }
      }
      
      if (!idToken || !user) {
        // Real invalid credentials
        return res.status(401).json({ error: "Invalid email address or password. Please check your credentials." });
      }
    }

    res.json({
      success: true,
      token: idToken,
      user
    });
  } catch (error: any) {
    console.error("Custom login failed:", error);
    res.status(500).json({ error: error.message || "Failed to log in." });
  }
});

// Auth API - Log Out placeholder
app.post("/api/auth/logout", (req, res) => {
  res.json({ success: true });
});

// Modular API routes
app.post("/api/create-order", createOrderHandler);
app.post("/api/verify-payment", verifyPaymentHandler);
app.post("/api/razorpay/order", razorpayOrderHandler);
app.post("/api/razorpay/verify", razorpayVerifyHandler);
app.post("/api/ocr", ocrHandler);

// Firebase Config API - Expose public configuration keys safely
app.get("/api/firebase-config", (req, res) => {
  try {
    let config: any = {
      apiKey: process.env.FIREBASE_API_KEY,
      authDomain: process.env.FIREBASE_AUTH_DOMAIN,
      projectId: process.env.FIREBASE_PROJECT_ID,
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
      messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
      appId: process.env.FIREBASE_APP_ID,
      firestoreDatabaseId: process.env.FIREBASE_FIRESTORE_DATABASE_ID
    };

    const configPath = path.join(process.cwd(), "firebase-applet-config.json");
    if (fs.existsSync(configPath)) {
      const fileConfig = JSON.parse(fs.readFileSync(configPath, "utf8"));
      config.apiKey = config.apiKey || fileConfig.apiKey;
      config.authDomain = config.authDomain || fileConfig.authDomain;
      config.projectId = config.projectId || fileConfig.projectId;
      config.storageBucket = config.storageBucket || fileConfig.storageBucket;
      config.messagingSenderId = config.messagingSenderId || fileConfig.messagingSenderId;
      config.appId = config.appId || fileConfig.appId;
      config.firestoreDatabaseId = config.firestoreDatabaseId || fileConfig.firestoreDatabaseId;
    }

    // Absolute robust default fallback values for this specific project
    config.apiKey = config.apiKey || "AIzaSyCFyGzp7viV1tq25DAMnpKKSJpPngtVa14";
    config.authDomain = config.authDomain || "gen-lang-client-0844549707.firebaseapp.com";
    config.projectId = config.projectId || "gen-lang-client-0844549707";
    config.storageBucket = config.storageBucket || "gen-lang-client-0844549707.firebasestorage.app";
    config.messagingSenderId = config.messagingSenderId || "845800015860";
    config.appId = config.appId || "1:845800015860:web:a6229be704605991785ba1";
    config.firestoreDatabaseId = config.firestoreDatabaseId || "ai-studio-imagetogeminipro-7991f626-f4c5-4d1c-8e24-82965df261a7";

    res.json(config);
  } catch (err: any) {
    console.error("Error fetching firebase config in Express:", err);
    res.status(500).json({ error: "Failed to load firebase config" });
  }
});

// Razorpay API - Get Config
app.get("/api/payment/razorpay-config", (req, res) => {
  try {
    const keyId = process.env.RAZORPAY_KEY_ID;
    res.json({
      keyId: keyId || "rzp_test_placeholder_key",
      isSandbox: !keyId
    });
  } catch (error: any) {
    res.status(500).json({ error: "Failed to load payment configuration" });
  }
});

// Razorpay API - Create Payment Order
app.post("/api/payment/create-order", async (req, res) => {
  try {
    const profile = await getAuthenticatedUser(req);
    if (!profile) {
      return res.status(401).json({ error: "Unauthorized. Please log in first." });
    }

    const { amount, currency, credits } = req.body;
    if (!amount || Number(amount) <= 0) {
      return res.status(400).json({ error: "Invalid purchase amount." });
    }

    const finalCurrency = currency || "INR";
    const amountInPaise = Math.round(Number(amount) * 100);

    const keyId = process.env.RAZORPAY_KEY_ID;
    const keySecret = process.env.RAZORPAY_KEY_SECRET;

    if (!keyId || !keySecret) {
      // Sandbox Mode: Return mock order details
      const simulatedOrderId = "order_sim_" + Math.random().toString(36).substring(2, 12);
      return res.json({
        success: true,
        isSandbox: true,
        orderId: simulatedOrderId,
        amount: amountInPaise,
        currency: finalCurrency,
        credits: credits
      });
    }

    // Real Razorpay integration
    const razorpay = new (Razorpay as any)({
      key_id: keyId,
      key_secret: keySecret
    });

    const options = {
      amount: amountInPaise,
      currency: finalCurrency,
      receipt: "receipt_order_" + Date.now() + "_" + Math.floor(Math.random() * 1000)
    };

    const order = await razorpay.orders.create(options);
    res.json({
      success: true,
      isSandbox: false,
      orderId: order.id,
      amount: order.amount,
      currency: order.currency,
      credits: credits
    });

  } catch (error: any) {
    console.error("Razorpay order creation error:", error);
    res.status(500).json({ error: error.message || "Failed to create payment order" });
  }
});

// Razorpay API - Verify Payment Signature & Credit User
app.post("/api/payment/verify", async (req, res) => {
  try {
    const profile = await getAuthenticatedUser(req);
    if (!profile) {
      return res.status(401).json({ error: "Unauthorized. Please log in first." });
    }

    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, credits, isSandbox } = req.body;

    if (!credits || Number(credits) <= 0) {
      return res.status(400).json({ error: "Invalid credits count." });
    }

    let isVerified = false;

    if (isSandbox || !process.env.RAZORPAY_KEY_SECRET) {
      // Sandbox: skip crypt signature check
      isVerified = true;
    } else {
      // Real HMAC verification
      const hmac = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET);
      hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
      const generatedSignature = hmac.digest("hex");
      isVerified = generatedSignature === razorpay_signature;
    }

    if (!isVerified) {
      return res.status(400).json({ error: "Payment verification failed. Invalid signature." });
    }

    // Credit user's account in Firestore
    const updatedUser = await firestoreDb.addCredits(profile.email, Number(credits), profile.idToken);
    if (!updatedUser) {
      return res.status(404).json({ error: "User profile not found." });
    }

    res.json({
      success: true,
      credits: updatedUser.credits,
      added: Number(credits),
      promptHistory: updatedUser.promptHistory || []
    });

  } catch (error: any) {
    console.error("Razorpay verification error:", error);
    res.status(500).json({ error: error.message || "Payment verification failed" });
  }
});

// User API - Add Credits (Checkout Sim)
app.post("/api/user/add-credits", async (req, res) => {
  try {
    const profile = await getAuthenticatedUser(req);
    if (!profile) {
      return res.status(401).json({ error: "Unauthorized. Please log in first." });
    }

    const { amount } = req.body;
    if (!amount || Number(amount) < 5) {
      return res.status(400).json({ error: "Minimum purchase amount is $5." });
    }

    // Give 50 credits on $5, and proportional credits for larger amounts
    const creditsToAdd = Math.floor((Number(amount) / 5) * 50);
    const updatedUser = await firestoreDb.addCredits(profile.email, creditsToAdd, profile.idToken);

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      success: true,
      credits: updatedUser.credits,
      added: creditsToAdd,
      promptHistory: updatedUser.promptHistory || []
    });
  } catch (error: any) {
    res.status(500).json({ error: "Payment checkout simulation failed" });
  }
});

// Initialize Gemini client with standard user agent
const apiKey = process.env.GEMINI_API_KEY;
const ai = new GoogleGenAI({
  apiKey: apiKey,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});

// API Route for prompt generation
app.post("/api/generate-prompt", async (req, res) => {
  try {
    const { image, mimeType, promptType, customInstructions } = req.body;

    if (!image) {
      return res.status(400).json({ error: "Missing image data" });
    }

    // Check Authentication
    const profile = await getAuthenticatedUser(req);
    let userEmail = profile ? profile.email : null;
    
    if (userEmail && profile) {
      // Enforce credits check
      if (profile.credits < 30) {
        return res.status(403).json({
          error: "credits_exhausted",
          message: "You have used all your free uses. Please upgrade starting from $5 to get 50 credits."
        });
      }
    }

    // Clean base64 string
    const base64Data = image.replace(/^data:image\/\w+;base64,/, "");

    // Determine target system instruction / prompt style based on options
    let promptText = "";
    if (promptType === "recreation") {
      promptText = "Create a detailed text-to-image prompt (for Midjourney/Stable Diffusion/Gemini) that captures every detail of this image so a model can recreate it perfectly. Analyze style, subject, composition, background, camera angle, lens, lighting (direction, intensity), colors, textures, and atmosphere. Output ONLY the raw final prompt in a concise, copyable format. Do not write 'Here is your prompt' or put it in quotes.";
    } else if (promptType === "artistic") {
      promptText = "Analyze this image and generate an artistic, poetic, and atmospheric text prompt. Focus on the emotional vibe, art style (e.g. oil painting, synthwave, watercolor, minimalist), lighting style, color palette, and visual metaphors. Output ONLY the raw final prompt. No introductory or concluding text.";
    } else if (promptType === "minimalist") {
      promptText = "Create a short, punchy, minimalist prompt capturing the core essence of this image. Keep it under 20-30 words, focusing only on the absolute key elements. Output ONLY the raw final prompt. No commentary.";
    } else {
      // Default: descriptive
      promptText = "Write a comprehensive descriptive prompt based on this image. Detail the main subject, background elements, lighting style, color scheme, and mood. Output ONLY the raw prompt. No extra text.";
    }

    if (customInstructions && customInstructions.trim() !== "") {
      promptText += ` Additional instructions/guidelines: ${customInstructions}`;
    }

    const imagePart = {
      inlineData: {
        mimeType: mimeType || "image/jpeg",
        data: base64Data,
      },
    };

    const textPart = {
      text: promptText,
    };

    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: { parts: [imagePart, textPart] },
    });

    const generatedPrompt = response.text || "Could not generate a prompt.";

    // If authenticated user, deduct 30 credits and record in prompt history
    let remainingCredits = null;
    if (userEmail && profile) {
      const success = await firestoreDb.deductCredit(userEmail, 30, profile.idToken);
      if (success) {
        const updatedUser = await firestoreDb.addPromptToHistory(userEmail, promptType, customInstructions, generatedPrompt, profile.idToken);
        if (updatedUser) {
          remainingCredits = updatedUser.credits;
        }
      }
    }

    res.json({ 
      prompt: generatedPrompt, 
      credits: remainingCredits 
    });
  } catch (error: any) {
    console.error("Gemini API Error:", error);
    res.status(500).json({ error: error.message || "An unexpected error occurred." });
  }
});

// Setup dev server or static distribution
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
    console.log("Vite dev server middleware mounted.");
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
    console.log("Serving static build from /dist.");
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

if (process.env.VERCEL !== "1") {
  startServer();
}

export default app;
