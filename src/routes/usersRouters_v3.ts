import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";

import dotenv from "dotenv";
dotenv.config();

import type { User, CustomRequest } from "../libs/types.ts";

// import authentication middleware
import { authenticateToken } from "../middlewares/authenMiddleware.ts";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminDBMiddleware.ts";
import { checkRoles } from "../middlewares/checkRolesDBMiddleware.ts";

// Password
import { comparePassword } from "../utils/compare.ts";
import { hashPassword } from "../utils/hash.ts";

// import database
import { PrismaClient } from "../../generated/prisma/client.ts";
const prisma = new PrismaClient();


// Validators
import { zUserBody } from "../libs/zodValidators.ts";

const router = Router();

// GET /api/v3/users

// GET /api/v3/users/:userId

// POST /api/v3/users/login
router.post("/login", async (req: Request, res: Response) => {
  try {
    // get username and password from body
    const { username, password } = req.body;
    // get a user from DB by username
    const user = await prisma.user.findUnique({
      where: {
        username: username,
      },
    });

    // if user not found
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    // found a user, compare passwords
    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    // create jwt token
    const jwt_secret = process.env.JWT_SECRET || "this_is_my_secret";
    const token = jwt.sign(
      {
        // create JWT Payload
        username: user.username,
        studentId: user.studentId,
        role: user.role,
      },
      jwt_secret,
      { expiresIn: "30m" }
    );

    // store the new token in user.tokens
    user.tokens = user.tokens ? [...user.tokens, token] : [token];

    // update user.tokens in the DB
    const updatedUser = await prisma.user.update({
      where: {
        username: user.username,
      },
      data: {
        tokens: user.tokens,
      },
    });

    return res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        username: user.username,
        tokens: user.tokens,
      }
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// POST /api/v3/users/logout
router.post("/logout", authenticateToken, async (req: CustomRequest, res: Response) => {
  try {
    const payload = req.user;
    const token = req.token;
    // get a user from DB by username from payload
    const user = await prisma.user.findUnique({
      where: {
        username: payload?.username,
      },
    });

    // if user not found
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    // delete all tokens by setting array size = 0
    user.tokens.length = 0;

    // update user.tokens on DB
    const updatedUser = await prisma.user.update({
      where: { username: user.username },
      data: { tokens: user.tokens }
    });

    return res.status(200).json({
      success: true,
      message: "Logout successful",
      data: updatedUser
    });

  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// POST /api/v3/users
router.post(
  "/",
  authenticateToken,    // check valid token, extract user payload
  checkRoleAdmin,       // check payload === 'ADMIN'
  async(req:CustomRequest, res:Response) => {
  try {
    // get new user information from req.body
    const body = (await req.body) as User;

    // validate req.body with predefined validator
    const result = zUserBody.safeParse(body);
    if (!result.success) {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        errors: result.error.issues[0]?.message,
      });
    }

    // get user with specified username OR studentId from DB
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          {username: body.username},
          {studentId: body.studentId}
        ]
      },
    });

    // if username OR studentId is already taken
    if (user) {
      return res.status(400).json({
        success: false,
        message: "Username or StudentID is already taken.",
      });
    }

    // if no user found, 
    // create new user with encrypted password
    const new_user:User = {
      username: body.username,
      password: await hashPassword(body.password,10),
      studentId: body.studentId ? body.studentId:null,
      role: body.role
    };
    // add new user to DB
    const created = await prisma.user.create({ data: new_user as any });

    // add response header 'Link'
    res.set("Link", `/api/v3/users/${created.id}`);

    return res.status(201).json({
      success: true,
      data: {
        if : created.id,
        username : created.username,
        createdAi : created.updatedAt
      }
    });

  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// DELETE /api/v3/users
router.delete("/",
  authenticateToken,
  checkRoleAdmin,
  async (req: CustomRequest, res: Response) => {
    try {
      // get username to delete from req.body
      const username = req.body.username as string;
      
      // check if the user does exist
      const user = await prisma.user.findUnique({
        where: { username: username}
      });
      if (!user) {
        return res.status(404).json({
          success: false,
          message: `User ${username} not found.`
        })
      }

      // found user, delete the user from DB
      const deletedUser = await prisma.user.delete({
        where: { username: username }
      });

      res.status(200).json({
        success: true,
        message: `User ${username} was deleted successfully.`,
        data: deletedUser
      });

    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);

export default router;
