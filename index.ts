import express, { Express, Request, Response } from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import { SystemuserRouter } from "./routes";
import * as Sentry from "@sentry/node";
import cors from 'cors';
dotenv.config();
import "./config/production/env_config";
console.clear();

const app: Express = express();
const port = Number(process.env.COMPRESS_CRM_PORT) || 3000; // fallback port
const localIp = "192.168.0.105"; // Your local IP address

// Initialize Sentry
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  serverName: "Compress Crm Backend",
  profilesSampleRate: 1.0,
});

// Configure CORS
const corsOptions = {
  origin: process.env.NODE_ENV === 'production'
    ? ['https://develop-0-0-1.d3rsax9971xrm5.amplifyapp.com/']
    : ['http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,

};

// Request Middleware
app.use(express.json());
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.urlencoded({ extended: true }));


// Routes
app.use("/api/v1/olxified", SystemuserRouter);

app.get("/", (req: Request, res: Response) => {
  res.send("Express + TypeScript server is running.");
});

// Start server and bind to 0.0.0.0 for local network access
app.listen(port, "0.0.0.0", () => {
  console.log(`⚡️[server]: Server is running at http:${localIp}:${port}`);
});


