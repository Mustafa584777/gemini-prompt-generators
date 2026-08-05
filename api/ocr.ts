import { Request, Response } from "express";
import { ai } from "./config";

export default async function handler(req: Request, res: Response) {
  try {
    const { image, mimeType } = req.body;
    if (!image) {
      return res.status(400).json({ error: "Missing image data" });
    }

    const base64Data = image.replace(/^data:image\/\w+;base64,/, "");
    
    // Call Gemini to do text extraction / description
    const response = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: {
        parts: [
          {
            inlineData: {
              mimeType: mimeType || "image/jpeg",
              data: base64Data
            }
          },
          {
            text: "Extract and return all visible text from this image. If no clear text is present, describe the key visual elements concisely. Output only the extracted text/description."
          }
        ]
      }
    });

    res.json({
      success: true,
      text: response.text || "No text detected."
    });
  } catch (error: any) {
    console.error("OCR / Vision error:", error);
    res.status(500).json({ error: error.message || "Failed to process image" });
  }
}
