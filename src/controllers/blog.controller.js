import Blog from "../models/blog.schema.js";

export const getBlogs = async (req, res) => {
  try {
    const blogs = await Blog.find();
    res.status(400).json(blogs);
  } catch (error) {
    console.log(error);
    res.status(400).json({ message: "Erreur de la récupération des blogs" });
  }
};
