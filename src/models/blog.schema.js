import mongoose from "mongoose";

const blogSchema = new mongoose.Schema(
  {
    titre: { type: String, required: true },
    texte: { type: String, required: true },
    image: { type: String, required: true },
    date: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

const Blog = mongoose.model("Blog", blogSchema);

export default Blog;
