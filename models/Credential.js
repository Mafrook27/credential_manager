const mongoose = require("mongoose");

const credentialSchema = new mongoose.Schema({
  subInstance: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubInstance",
    required: true
  },
  rootInstance: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "RootInstance",
    required: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "C_User",
    required: true
  },
  sharedWith: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "C_User"
  }],
  fields: [
    {
      key: {
        type: String,
        required: true
      },
      value: {
        type: String,
        required: true
      }
    }
  ],
  notes: {
    type: String,
    default: ''
  },
  lastAccessed: {
    type: Date
  },
  isDeleted: {
    type: Boolean,
    default: false,
    index: true
  },
  deletedAt: {
    type: Date,
    default: null
  },
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "C_User",
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { versionKey: false });

credentialSchema.index({ createdBy: 1 });
credentialSchema.index({ createdBy: 1, isDeleted: 1 });
credentialSchema.index({ sharedWith: 1 });
credentialSchema.index({ sharedWith: 1, isDeleted: 1 });
credentialSchema.index({ rootInstance: 1 });
credentialSchema.index({ subInstance: 1 });
credentialSchema.index({ isDeleted: 1, createdAt: -1 });
credentialSchema.index({ createdBy: 1, sharedWith: 1, isDeleted: 1 });

module.exports = mongoose.model("Credential", credentialSchema);
