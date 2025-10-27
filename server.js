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
app.use(cors({
  origin: [
    "http://localhost:5173",  
    "http://localhost:5000",  
    "https://amiee-cismontane-fredricka.ngrok-free.dev",
    "https://credentialmanager-jjq62i0pj-mafrook27s-projects.vercel.app"
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type']
}));


app.use(helmet());
app.set('trust proxy', true)
app.use(express.json());
app.use(attachRequestId);

app.use(requestLogger);
app.use(activityTrackerMiddleware);

// Swagger Documentation

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs, {explorer: true}));

app.use("/api/h", (req, res) => res.send("API is running..."));
app.use("/api", apiroutes);
app.get('/swagger.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(specs); // specs is your OpenAPI object
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
    stack: err.stack
  });
  
  res.status(statusCode).json({
    success: false,
    message: err.message || 'Server Error'
  });
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  logger.info(`Server running on http://localhost:${PORT}`)
);



