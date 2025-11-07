const express = require("express");
const dotenv = require("dotenv");
const connectDB = require("./Config/Db");
const logger = require("./util/Logger");
const requestLogger = require("./util/reqLogger");
const { swaggerUi, specs } = require('./Config/swagger');
const apiroutes = require("./Routes/Index");
const cookieParser = require('cookie-parser');

const {
  activityTrackerMiddleware,
  attachRequestId
} = require("./Middleware/activityTracker");
const helmet = require("helmet");
const cors = require("cors");
dotenv.config();
connectDB();

const app = express();
app.use(cookieParser());
// CORS configuration - Allow frontend origins (configurable via env)
// Defaults for local dev
const defaultAllowedOrigins = [
  "http://localhost:5173",
  "http://localhost:5000",
  "http://localhost:3000",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:5000",
  "http://127.0.0.1:3000"
];

// Support either ALLOWED_ORIGINS (comma-separated) or legacy FRONTEND_URL
const envAllowedOrigins = ((process.env.ALLOWED_ORIGINS || process.env.FRONTEND_URL || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean));

// Include backend's own URL if the server makes self-calls from a browser context or for tools that enforce CORS
const selfUrl = (process.env.BACKEND_URL || process.env.SELF_URL || "").trim();

const allowedOrigins = Array.from(new Set([
  ...defaultAllowedOrigins,
  ...envAllowedOrigins,
  ...(selfUrl ? [selfUrl] : [])
]));

const corsOptions = {
  origin: function (origin, callback) {
    // Allow non-browser requests with no Origin (e.g., curl, server-to-server, Postman, Hoppscotch)
    if (!origin) return callback(null, true);

    // In development, allow all origins for testing tools
    if (process.env.NODE_ENV === 'development' || !process.env.NODE_ENV) {
      return callback(null, true);
    }

    // In production, check allowed origins
    if (allowedOrigins.includes(origin)) {
      logger.info(`✅ CORS allowed for origin: ${origin}`);
      return callback(null, true);
    }

    logger.warn(`🚫 CORS blocked origin: ${origin}. Allowed origins: ${allowedOrigins.join(', ')}`);
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));


app.use(helmet());
app.set('trust proxy', true)
app.use(express.json());
app.use(attachRequestId);

app.use(requestLogger);
app.use(activityTrackerMiddleware);

// Swagger Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs, { explorer: true }));

// Health route
app.use("/api/h", (req, res) => res.send("API is running..."));

// API routes
app.use("/api", apiroutes);

// OpenAPI JSON
app.get('/swagger.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(specs);
});

// Error handler
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  res.locals.error = {
    message: err.message || 'Internal Server Error',
    stack: err.stack || null
  };
  logger.error('Error occurred', {
    requestId: req.requestId,
    message: err.message,
    statusCode: statusCode,
    code: err.code || null,
    stack: err.stack
  });
  res.status(statusCode).json({
    success: false,
    message: err.message || 'Server Error',
    code: err.code || null  // ✅ IMPORTANT: Send error code to frontend
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  const baseUrl = selfUrl || `http://localhost:${PORT}`;
  logger.info(`Server running on ${baseUrl}`)
});
