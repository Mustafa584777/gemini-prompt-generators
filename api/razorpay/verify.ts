import crypto from "crypto";
import { Request, Response } from "express";
import { RAZORPAY_KEY_SECRET } from "../config";

export function verifyRazorpaySignature(orderId: string, paymentId: string, signature: string): boolean {
  if (!orderId || !paymentId || !signature) {
    return false;
  }

  if (!process.env.RAZORPAY_KEY_SECRET) {
    // Sandbox mode
    return signature === "signature_sim_verified" || signature.startsWith("signature_sim_");
  }

  const hmac = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET);
  hmac.update(`${orderId}|${paymentId}`);
  const generatedSignature = hmac.digest("hex");
  return generatedSignature === signature;
}

export default async function handler(req: Request, res: Response) {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: "Missing required verification fields" });
    }

    const isValid = verifyRazorpaySignature(razorpay_order_id, razorpay_payment_id, razorpay_signature);
    if (!isValid) {
      return res.status(400).json({ error: "Payment verification failed. Invalid signature." });
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error("Error verifying payment:", error);
    res.status(500).json({ error: error.message || "Verification failed" });
  }
}
