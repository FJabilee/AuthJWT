import { JWT_REFRESH_SECRET, JWT_SECRET } from '../constants/env';
import { CONFLICT, UNAUTHORIZED } from '../constants/http';
import VerificationCodeType from '../constants/verificationCodeTypes';
import SessionModel from '../models/session.model';
import UserModel from '../models/user.model';
import VerificationCodeModel from '../models/verificationCode.model';
import appAssert from '../utils/appAssert';
import { oneYearFromNow } from '../utils/date';
import jwt, { sign } from 'jsonwebtoken';
import { RefreshTokenPayload, refreshTokenSignOptions, signToken, verifyToken } from '../utils/jwt';

export type CreateAccountParams = {
    // username: string;
    email: string;
    password: string;
    userAgent?: string;
}


export const createAccount = async (data: CreateAccountParams) => {
    // verify existing user doesnt exist // Change to email and add username.
    const existingUser = await UserModel.exists({
        email: data.email,
    })
    appAssert(!existingUser, CONFLICT, "Email already in use")

    // create user
    const user = await UserModel.create({
        email: data.email,
        password: data.password,
    });

    const userId = user._id;
    // create verication code
    const verificationCode = await VerificationCodeModel.create({
        userId,
        type: VerificationCodeType.EmailVerification,
        expiresAt: oneYearFromNow()
    })

    // send verification email

    // create session
    const session = await SessionModel.create({
        userId,
        userAgent: data.userAgent,
    });

    // sign access token & refresh token
    const refreshToken = signToken({ 
        sessionId: session._id },
        refreshTokenSignOptions 
    )

    const accessToken = signToken({ 
        userId,
        sessionId: session._id 
    });

    // return user & token
    return {
        user: user.omitPassword(),
        accessToken,
        refreshToken,
    };
};
type LoginParams = {
  email: string;
  password: string;
  userAgent?: string;
};

export const loginUser = async ({
    email, 
    password, 
    userAgent
}:LoginParams ) => {
    // get user by email
    const user = await UserModel.findOne({ email });
    appAssert(user, UNAUTHORIZED, "Invalid email or password");

    // validate password from the request
    const isValid = await user.comparePassword(password);
    appAssert(isValid, UNAUTHORIZED, "Invalid email or password");

    const userId = user._id;
    // create a session
    
    const session = await SessionModel.create({
        userId,
        userAgent
    });

    const sessionInfo = {
        sessionId: session._id,
      };

    // sign access token & refresh token
    const refreshToken = signToken(sessionInfo, refreshTokenSignOptions)

    const accessToken = signToken({
        ...sessionInfo,
        userId: user._id,
    })
    
    // return user & token
    return {
        user: user.omitPassword(),
        accessToken,
        refreshToken,
    };
};