import { Request, Response } from "express";
import { createRazorpayOrder } from "./razorpay/order";
import { getAuthenticatedUser } from "../server-firebase";

export default async function handler(req: Request, res: Response) {
  try {
    // Optional firebase auth check if available
    const user = await getAuthenticatedUser(req).catch(() => null);
    
    const { amount, currency, receipt } = req.body;
    if (!amount) {
      return res.status(400).json({ error: "Amount in paise is required" });
    }

    const amountNum = Number(amount);
    if (amountNum < 100) {
      return res.status(400).json({ error: "Amount must be at least 100 paise" });
    }

    const order = await createRazorpayOrder(amountNum, currency || "INR", receipt);
    res.json({
      success: true,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      isSandbox: order.isSandbox
    });
  } catch (error: any) {
    console.error("Error in create-order endpoint:", error);
    res.status(500).json({ error: error.message || "Internal server error" });
  }
}
