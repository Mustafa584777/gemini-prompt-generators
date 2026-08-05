import { Request, Response } from "express";
import { verifyRazorpaySignature } from "./razorpay/verify";
import { getAuthenticatedUser, firestoreDb } from "../server-firebase";

export default async function handler(req: Request, res: Response) {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, credits, isSandbox } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: "Missing payment identifiers" });
    }

    const isValid = verifyRazorpaySignature(razorpay_order_id, razorpay_payment_id, razorpay_signature);
    if (!isValid) {
      return res.status(400).json({ error: "Invalid payment signature verification failed" });
    }

    // Attempt to credit user if token and credits are specified
    const profile = await getAuthenticatedUser(req).catch(() => null);
    if (profile && profile.email && credits) {
      const authHeader = req.headers.authorization || req.headers.Authorization;
      const authStr = Array.isArray(authHeader) ? authHeader[0] : authHeader;
      const idToken = authStr && typeof authStr === "string" && authStr.toLowerCase().startsWith("bearer ") ? authStr.substring(7).trim() : undefined;
      
      const updatedUser = await firestoreDb.addCredits(profile.email, Number(credits), idToken);
      if (updatedUser) {
        return res.json({
          success: true,
          verified: true,
          credits: updatedUser.credits,
          added: Number(credits)
        });
      }
    }

    res.json({
      success: true,
      verified: true,
    });
  } catch (error: any) {
    console.error("Error in verify-payment endpoint:", error);
    res.status(500).json({ error: error.message || "Internal server error" });
  }
}
