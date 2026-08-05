import dotenv from "dotenv";
import Razorpay from "razorpay";
import { GoogleGenAI } from "@google/genai";

dotenv.config();

export const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || "rzp_test_TApxAqjEFezsaM";
export const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || "e9iGWkV3q1Lt8ZEzGgCXwH5m";

export const razorpayInstance = new (Razorpay as any)({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

export const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    }
  }
});
