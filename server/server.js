const express = require("express");
const cors = require("cors");
require("dotenv").config();

const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(cors());
app.use(express.json());

const API_KEY = process.env.VT_API_KEY;

if (!API_KEY) {
  console.error("❌ VT_API_KEY not found in .env");
  process.exit(1);
}

// =======================
// Scan URL
// =======================
app.post("/api/scan", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    const r = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: {
        "x-apikey": API_KEY,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    const data = await r.json();

    if (!data?.data?.id) {
      console.error("VirusTotal response:", data);
      return res.status(500).json({ error: "No analysis id from VirusTotal" });
    }

    res.json({
      analysisId: data.data.id
    });

  } catch (err) {
    console.error("SCAN ERROR:", err);
    res.status(500).json({ error: "Scan failed" });
  }
});

// =======================
// Get result
// =======================
app.get("/api/result/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const r = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${id}`,
      {
        headers: {
          "x-apikey": API_KEY,
        },
      }
    );

    const data = await r.json();
    res.json(data);

  } catch (err) {
    console.error("RESULT ERROR:", err);
    res.status(500).json({ error: "Result failed" });
  }
});

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
