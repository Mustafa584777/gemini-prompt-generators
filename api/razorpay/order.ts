import { Request, Response } from "express";
import { razorpayInstance } from "../config";

export async function createRazorpayOrder(amount: number, currency: string = "INR", receipt?: string) {
  if (!amount || amount < 100) {
    throw new Error("Amount must be at least 100 paise (1 INR)");
  }

  // If no real keys are configured, simulate sandbox order
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
    return {
      id: "order_sim_" + Math.random().toString(36).substring(2, 12),
      amount: amount,
      currency: currency,
      receipt: receipt || "receipt_" + Date.now(),
      isSandbox: true,
    };
  }

  const options = {
    amount,
    currency,
    receipt: receipt || "receipt_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
  };

  const order = await razorpayInstance.orders.create(options);
  return {
    id: order.id,
    amount: order.amount,
    currency: order.currency,
    receipt: order.receipt,
    isSandbox: false,
  };
}

export default async function handler(req: Request, res: Response) {
  try {
    const { amount, currency, receipt } = req.body;
    if (!amount) {
      return res.status(400).json({ error: "Amount is required" });
    }
    const order = await createRazorpayOrder(Number(amount), currency || "INR", receipt);
    res.json(order);
  } catch (error: any) {
    console.error("Error creating Razorpay order:", error);
    res.status(500).json({ error: error.message || "Failed to create order" });
  }
}
