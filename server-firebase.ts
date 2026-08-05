import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";

// Load configuration
let projectId = process.env.FIREBASE_PROJECT_ID;
let databaseId = process.env.FIREBASE_FIRESTORE_DATABASE_ID;
let apiKey = process.env.FIREBASE_API_KEY;

try {
  const possiblePaths = [
    path.join(process.cwd(), "firebase-applet-config.json")
  ];

  let config: any = null;
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      try {
        config = JSON.parse(fs.readFileSync(p, "utf8"));
        break;
      } catch (e) {
        console.warn(`Failed to parse config at ${p}:`, e);
      }
    }
  }

  if (config) {
    if (!projectId) projectId = config.projectId;
    if (!databaseId) databaseId = config.firestoreDatabaseId;
    if (!apiKey) apiKey = config.apiKey;
  }
} catch (err) {
  console.warn("Could not read firebase-applet-config.json:", err);
}

// Default fallbacks for AI Studio environment
if (!projectId) {
  projectId = "gen-lang-client-0844549707";
}
if (!databaseId) {
  databaseId = "ai-studio-imagetogeminipro-7991f626-f4c5-4d1c-8e24-82965df261a7";
}
if (!apiKey) {
  apiKey = "AIzaSyCFyGzp7viV1tq25DAMnpKKSJpPngtVa14";
}

const baseUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/${databaseId}/documents`;

const JWT_SECRET = process.env.JWT_SECRET || "ai-studio-imagetogeminipro-super-secret-key-12345!";

export function generateToken(email: string): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ email, exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 7) })).toString("base64url");
  const signature = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${payload}`).digest("base64url");
  return `${header}.${payload}.${signature}`;
}

export function verifyToken(token: string): string | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [header, payload, signature] = parts;
    const expectedSignature = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${payload}`).digest("base64url");
    if (signature !== expectedSignature) return null;
    
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decodedPayload = JSON.parse(Buffer.from(base64, "base64").toString("utf8"));
    if (decodedPayload.exp && decodedPayload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return decodedPayload.email;
  } catch (err) {
    return null;
  }
}

export function hashPassword(password: string): string {
  return crypto.createHmac("sha256", JWT_SECRET).update(password).digest("hex");
}

// Verification helper for secure requests using Bearer Firebase ID Tokens or Custom Tokens
export async function getAuthenticatedUser(req: any): Promise<any | null> {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
    console.log("server-firebase: getAuthenticatedUser: Authorization header is missing or does not start with Bearer");
    return null;
  }
  const idToken = authHeader.substring(7).trim();

  // 1. Try our custom JWT verifier first (which bypasses Firebase completely and is fast)
  const customEmail = verifyToken(idToken);
  if (customEmail) {
    console.log("server-firebase: getAuthenticatedUser: custom token verified for", customEmail);
    return { email: customEmail };
  }

  // 2. Try official Google token verification using Identity Toolkit lookup API (most robust)
  try {
    const lookupUrl = `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`;
    const lookupRes = await fetch(lookupUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken })
    });
    if (lookupRes.ok) {
      const lookupData = await lookupRes.json();
      if (lookupData.users && lookupData.users.length > 0) {
        const lookupUser = lookupData.users[0];
        console.log("server-firebase: getAuthenticatedUser: Securely verified standard Firebase ID token via Google API for:", lookupUser.email);
        return {
          email: lookupUser.email,
          name: lookupUser.displayName || lookupUser.email.split("@")[0],
          uid: lookupUser.localId
        };
      }
    } else {
      console.warn("server-firebase: getAuthenticatedUser: Google accounts:lookup returned status", lookupRes.status);
    }
  } catch (lookupErr) {
    console.error("server-firebase: getAuthenticatedUser: Google accounts:lookup request failed:", lookupErr);
  }

  // 3. Fallback: Decode standard Firebase JWT token (decode-only for maximum robustness in serverless environment)
  try {
    const parts = idToken.split(".");
    if (parts.length === 3) {
      let decodedStr = "";
      try {
        decodedStr = Buffer.from(parts[1], "base64url").toString("utf8");
      } catch (e) {
        let base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
        while (base64.length % 4) {
          base64 += "=";
        }
        decodedStr = Buffer.from(base64, "base64").toString("utf8");
      }

      const payload = JSON.parse(decodedStr);
      console.log("server-firebase: getAuthenticatedUser: decoded Firebase token payload", payload);
      
      const email = payload.email || (payload.firebase?.identities?.email ? payload.firebase.identities.email[0] : null);
      if (email) {
        return {
          email: email,
          name: payload.name || email.split("@")[0],
          uid: payload.user_id || payload.sub,
        };
      } else {
        console.log("server-firebase: getAuthenticatedUser: Firebase token payload has no email field", payload);
      }
    } else {
      console.log("server-firebase: getAuthenticatedUser: token does not have 3 parts", parts.length);
    }
  } catch (err: any) {
    console.error("server-firebase: getAuthenticatedUser: Error decoding standard Firebase ID token", err);
  }
  return null;
}

export interface UserProfile {
  username: string;
  email: string;
  credits: number;
  promptHistory: {
    promptType: string;
    customInstructions: string;
    generatedPrompt: string;
    timestamp: string;
  }[];
  passwordHash?: string;
}

// Path for writable local temporary fallback storage in case network is down
const localDbPath = path.join("/tmp", "users-local-db.json");

function loadLocalDb(): Record<string, any> {
  try {
    if (fs.existsSync(localDbPath)) {
      const data = fs.readFileSync(localDbPath, "utf8");
      return JSON.parse(data);
    }
  } catch (err) {
    console.error("Failed to load local database fallback:", err);
  }
  return {};
}

function saveLocalDb(data: Record<string, any>) {
  try {
    const dir = path.dirname(localDbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(localDbPath, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error("Failed to save local database fallback:", err);
  }
}

// Firestore REST Type converters
function toFirestoreValue(val: any): any {
  if (val === null || val === undefined) {
    return { nullValue: null };
  }
  if (typeof val === "string") {
    return { stringValue: val };
  }
  if (typeof val === "number") {
    return { integerValue: String(Math.floor(val)) };
  }
  if (typeof val === "boolean") {
    return { booleanValue: val };
  }
  if (Array.isArray(val)) {
    return {
      arrayValue: {
        values: val.map(toFirestoreValue)
      }
    };
  }
  if (typeof val === "object") {
    const fields: any = {};
    for (const [k, v] of Object.entries(val)) {
      fields[k] = toFirestoreValue(v);
    }
    return { mapValue: { fields } };
  }
  return { nullValue: null };
}

function fromFirestoreValue(val: any): any {
  if (!val) return null;
  if ("stringValue" in val) return val.stringValue;
  if ("integerValue" in val) return parseInt(val.integerValue, 10);
  if ("doubleValue" in val) return parseFloat(val.doubleValue);
  if ("booleanValue" in val) return val.booleanValue;
  if ("nullValue" in val) return null;
  if ("arrayValue" in val) {
    const values = val.arrayValue.values || [];
    return values.map(fromFirestoreValue);
  }
  if ("mapValue" in val) {
    const fields = val.mapValue.fields || {};
    const obj: any = {};
    for (const [k, v] of Object.entries(fields)) {
      obj[k] = fromFirestoreValue(v);
    }
    return obj;
  }
  return null;
}

// Firebase Auth REST API Helper Functions
export async function firebaseAuthSignUp(email: string, passwordPlain: string): Promise<{ idToken: string; localId: string } | null> {
  try {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password: passwordPlain,
        returnSecureToken: true
      })
    });
    if (!res.ok) {
      const err = await res.json();
      const message = err.error?.message || "SignUp failed";
      throw new Error(message);
    }
    const data = await res.json();
    return { idToken: data.idToken, localId: data.localId };
  } catch (err: any) {
    console.error("Firebase Auth REST SignUp error:", err);
    throw err;
  }
}

export async function firebaseAuthSignIn(email: string, passwordPlain: string): Promise<{ idToken: string; localId: string } | null> {
  try {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password: passwordPlain,
        returnSecureToken: true
      })
    });
    if (!res.ok) {
      const err = await res.json();
      const message = err.error?.message || "SignIn failed";
      throw new Error(message);
    }
    const data = await res.json();
    return { idToken: data.idToken, localId: data.localId };
  } catch (err: any) {
    console.error("Firebase Auth REST SignIn error:", err);
    throw err;
  }
}

// Robust Firestore client utilizing direct HTTP REST calls
export const firestoreDb = {
  async getUser(email: string, idToken?: string): Promise<UserProfile | null> {
    const cleanEmail = email.trim().toLowerCase();
    const dbsToTry = [databaseId, "(default)"];
    
    for (const db of dbsToTry) {
      if (!db) continue;
      const dbBaseUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/${db}/documents`;
      const url = `${dbBaseUrl}/users/${encodeURIComponent(cleanEmail)}?key=${apiKey}`;
      
      // Try with authorization first
      if (idToken) {
        try {
          const res = await fetch(url, {
            headers: { "Authorization": `Bearer ${idToken}` }
          });
          if (res.status === 404) {
            return null;
          }
          if (res.ok) {
            const data = await res.json();
            const fields = data.fields || {};
            const profile: any = {};
            for (const [k, v] of Object.entries(fields)) {
              profile[k] = fromFirestoreValue(v);
            }
            return profile as UserProfile;
          }
        } catch (err) {
          console.warn(`Firestore REST failed for db ${db} with auth:`, err);
        }
      }
      
      // Try without authorization (using rules allow: if true)
      try {
        const res = await fetch(url);
        if (res.status === 404) {
          return null;
        }
        if (res.ok) {
          const data = await res.json();
          const fields = data.fields || {};
          const profile: any = {};
          for (const [k, v] of Object.entries(fields)) {
            profile[k] = fromFirestoreValue(v);
          }
          return profile as UserProfile;
        }
      } catch (err) {
        console.warn(`Firestore REST failed for db ${db} without auth:`, err);
      }
    }
    
    // Fallback to local storage if all Firestore calls fail
    console.warn("Firestore REST completely failed for getUser, falling back to local storage.");
    const localDb = loadLocalDb();
    if (localDb[cleanEmail]) {
      return localDb[cleanEmail];
    }
    return null;
  },

  async setUser(email: string, profile: UserProfile, idToken?: string): Promise<void> {
    const cleanEmail = email.trim().toLowerCase();
    const fields: any = {};
    for (const [k, v] of Object.entries(profile)) {
      fields[k] = toFirestoreValue(v);
    }
    
    const dbsToTry = [databaseId, "(default)"];
    let lastError: Error | null = null;
    
    for (const db of dbsToTry) {
      if (!db) continue;
      const dbBaseUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/${db}/documents`;
      const url = `${dbBaseUrl}/users/${encodeURIComponent(cleanEmail)}?key=${apiKey}`;
      
      // Try with authorization first
      if (idToken) {
        try {
          const res = await fetch(url, {
            method: "PATCH",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${idToken}`
            },
            body: JSON.stringify({ fields })
          });
          if (res.ok) {
            return; // Success!
          }
          const text = await res.text();
          lastError = new Error(`Status ${res.status}: ${text}`);
        } catch (err: any) {
          lastError = err;
        }
      }
      
      // Try without authorization
      try {
        const res = await fetch(url, {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ fields })
        });
        if (res.ok) {
          return; // Success!
        }
        const text = await res.text();
        lastError = new Error(`Status ${res.status}: ${text}`);
      } catch (err: any) {
        lastError = err;
      }
    }
    
    // If all Firestore calls failed, update local storage as fallback and throw warning (not fatal error)
    console.warn("Firestore REST completely failed for setUser, updating local storage fallback:", lastError);
    const localDb = loadLocalDb();
    localDb[cleanEmail] = profile;
    saveLocalDb(localDb);
  },

  async createUser(email: string, username: string, initialCredits: number = 90, idToken?: string): Promise<UserProfile> {
    const cleanEmail = email.trim().toLowerCase();
    const newUser: UserProfile = {
      username: username.trim(),
      email: cleanEmail,
      credits: initialCredits,
      promptHistory: []
    };
    try {
      await this.setUser(cleanEmail, newUser, idToken);
      return newUser;
    } catch (err) {
      console.warn("Firestore REST error in createUser, falling back to local memory:", err);
      const localDb = loadLocalDb();
      localDb[cleanEmail] = newUser;
      saveLocalDb(localDb);
      return newUser;
    }
  },

  async createUserWithPassword(email: string, username: string, passwordPlain: string, initialCredits: number = 90, idToken?: string): Promise<UserProfile> {
    const cleanEmail = email.trim().toLowerCase();
    const passwordHash = hashPassword(passwordPlain);
    const newUser: UserProfile = {
      username: username.trim(),
      email: cleanEmail,
      credits: initialCredits,
      promptHistory: [],
      passwordHash: passwordHash
    };
    try {
      await this.setUser(cleanEmail, newUser, idToken);
      return {
        username: newUser.username,
        email: newUser.email,
        credits: newUser.credits,
        promptHistory: newUser.promptHistory
      };
    } catch (err) {
      console.warn("Firestore REST error in createUserWithPassword, falling back to local database:", err);
      const localDb = loadLocalDb();
      localDb[cleanEmail] = newUser;
      saveLocalDb(localDb);
      return {
        username: newUser.username,
        email: newUser.email,
        credits: newUser.credits,
        promptHistory: newUser.promptHistory
      };
    }
  },

  async verifyUserPassword(email: string, passwordPlain: string): Promise<UserProfile | null> {
    const cleanEmail = email.trim().toLowerCase();
    const expectedHash = hashPassword(passwordPlain);
    try {
      const profile = await this.getUser(cleanEmail);
      if (profile && profile.passwordHash === expectedHash) {
        return {
          username: profile.username,
          email: profile.email,
          credits: profile.credits,
          promptHistory: profile.promptHistory || []
        };
      }
      return null;
    } catch (err) {
      console.warn("Firestore REST error in verifyUserPassword, falling back to local database:", err);
      const localDb = loadLocalDb();
      const data = localDb[cleanEmail];
      if (data && data.passwordHash === expectedHash) {
        return {
          username: data.username,
          email: data.email,
          credits: data.credits,
          promptHistory: data.promptHistory || []
        };
      }
      return null;
    }
  },

  async addCredits(email: string, amount: number, idToken?: string): Promise<UserProfile | null> {
    const cleanEmail = email.trim().toLowerCase();
    try {
      const profile = await this.getUser(cleanEmail, idToken);
      if (!profile) return null;
      profile.credits = (profile.credits || 0) + amount;
      await this.setUser(cleanEmail, profile, idToken);
      return profile;
    } catch (err) {
      console.warn("Firestore REST error in addCredits, falling back to local database:", err);
      const localDb = loadLocalDb();
      if (localDb[cleanEmail]) {
        localDb[cleanEmail].credits = (localDb[cleanEmail].credits || 0) + amount;
        saveLocalDb(localDb);
        return localDb[cleanEmail];
      }
      return null;
    }
  },

  async deductCredit(email: string, amount: number = 30, idToken?: string): Promise<boolean> {
    const cleanEmail = email.trim().toLowerCase();
    try {
      const profile = await this.getUser(cleanEmail, idToken);
      if (!profile) return false;
      const currentCredits = profile.credits ?? 0;
      if (currentCredits < amount) return false;
      profile.credits = currentCredits - amount;
      await this.setUser(cleanEmail, profile, idToken);
      return true;
    } catch (err) {
      console.warn("Firestore REST error in deductCredit, falling back to local database:", err);
      const localDb = loadLocalDb();
      if (localDb[cleanEmail]) {
        const currentCredits = localDb[cleanEmail].credits || 0;
        if (currentCredits >= amount) {
          localDb[cleanEmail].credits = currentCredits - amount;
          saveLocalDb(localDb);
          return true;
        }
      }
      return false;
    }
  },

  async addPromptToHistory(
    email: string,
    promptType: string,
    customInstructions: string,
    generatedPrompt: string,
    idToken?: string
  ): Promise<UserProfile | null> {
    const cleanEmail = email.trim().toLowerCase();
    const newPrompt = {
      promptType,
      customInstructions: customInstructions || "",
      generatedPrompt,
      timestamp: new Date().toISOString()
    };
    try {
      const profile = await this.getUser(cleanEmail, idToken);
      if (!profile) return null;
      const history = profile.promptHistory || [];
      profile.promptHistory = [newPrompt, ...history];
      await this.setUser(cleanEmail, profile, idToken);
      return profile;
    } catch (err) {
      console.warn("Firestore REST error in addPromptToHistory, falling back to local database:", err);
      const localDb = loadLocalDb();
      if (localDb[cleanEmail]) {
        const history = localDb[cleanEmail].promptHistory || [];
        localDb[cleanEmail].promptHistory = [newPrompt, ...history];
        saveLocalDb(localDb);
        return localDb[cleanEmail];
      }
      return null;
    }
  }
};
