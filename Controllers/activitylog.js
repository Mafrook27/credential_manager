const ActivityLog = require('../models/activity');
const getActivityLogs = async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 10,
      username,
      isslow,
      iserror,
      startdate,
      enddate,
      sortby,
      sortorder
    } = req.query;

    const query = {};

    // Username filter
    if (username) query.userName = new RegExp(username, 'i');

    // Status filters
    if (isslow !== undefined) query.isSlowResponse = isslow === 'true';
    if (iserror !== undefined) query.hasError = iserror === 'true';

    // Date range filter
    if (startdate || enddate) {
      query.timestamp = {};
      if (startdate) {
        query.timestamp.$gte = new Date(startdate);
      }
      if (enddate) {
        const end = new Date(enddate);
        end.setHours(23, 59, 59, 999);
        query.timestamp.$lte = end;
      }
    }

    // Get total count
    const total = await ActivityLog.countDocuments(query);

    // Build sort object
    const sortField = sortby || 'timestamp';
    const sortDir = sortorder === 'asc' ? 1 : -1;
    const sortObj = { [sortField]: sortDir };

    // Get paginated logs with dynamic sorting
    const logs = await ActivityLog.find(query)
      .sort(sortObj)
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit))
      .lean();

    res.json({
      success: true,
      data: logs,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getActivityLogs
};