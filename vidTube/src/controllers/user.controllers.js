import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.models.js"
import { uploadOnCloudinary, deleteFromCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { jwt } from "jsonwebtoken";

const generateAccessAndRefreshToken = async(userId) => {
    try {
        const user = await User.findById(userId);
        if(!user){
            throw new ApiError(402, "user not found");
        } 
    
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
    
        user.refreshToken = refreshToken;
        await user.save({ValidateBeforeSave: false});
        
        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError(500, "Something went wrong while creating access and refresh token");
    }
}

const registerUser = asyncHandler( async(req, res) => {
    const {fullname, email, username, password} = req.body;

    // validation
    if(
        [fullname, username, email, password].some(field => field?.trim() === "")
    ){
        throw new ApiError(400, "All fields are required");
    }
    const existedUser = await User.findOne({
        $or: [{username}, {email}]
    })
    
    if(existedUser){
        throw new ApiError(409, "User already exists with these credentials");
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    const coverLocalPath = req.files?.coverImage[0]?.path

    if(!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing");
    }

    // const avatar = uploadOnCloudinary(avatarLocalPath)
    // const coverImage = "";
    // if(coverLocalPath) {
    //     coverImage = uploadOnCloudinary(coverImage)
    // }

    let avatar;
    try {
        avatar = await uploadOnCloudinary(avatarLocalPath);
        console.log("uploaded avatar", avatar);
    } catch (error) {
        console.log("Error uploading avatar", error);
        throw new ApiError(500, "avatar file is missing");
    }

    let coverImage;
    try {
        coverImage = await uploadOnCloudinary(coverLocalPath);
        console.log("uploaded coverImage", coverImage);
    } catch (error) {
        console.log("Error uploading coverImage", error);
        throw new ApiError(500, "coverImage file is missing");
    }

    try {
        const user = await User.create({
            fullname,
            avatar: avatar.url,
            coverImage: coverImage?.url || "",
            email,
            password,
            username: username.toLowerCase()
        })
    
        const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
        )
    
        if(createdUser) {
            throw new ApiError(500, "something went wrong while creating user");
        }
    
        return res
        .status(201)
        .json(new ApiResponse(200, createdUser, "User registered successfully"));
    } catch (error) {
        console.log("user creation failed")

        if(avatar){
            deleteFromCloudinary(avatar.public_id)

        }
        if(coverImage){
            deleteFromCloudinary(coverImage.public_id)
        }

        throw new ApiError(500, "something went wrong while creating user and images were deleted");
    }

    
});

const loginUser = asyncHandler( async(req, res) => {
    const {email, username, password} = req.body;

    if(!email){
        throw new ApiError(400, "Email is required");
    }

    const user = await User.findOne({
        $or: [{username}, {email}]
    })

    if(!user){
        throw new ApiError(404, "User not found");
    }

    //validate password
    const isPasswordValid = await user.isPasswordCorrect(password);

    if(!isPasswordValid) {
        throw new ApiError(401, "Invalid credentials");
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id)
     .select("-password -refreshToken");
    
    if(!loggedInUser){
        throw new ApiError(401, "user not found");
    }

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production"
    }

    return res.status(200).cookie("accessToken", accessToken, options)
     .cookie("refreshToken", refreshToken, options)
     .json(new ApiResponse(200, loggedInUser, "user loggedin Successfully"));
})

const logoutUser = asyncHandler( async(req, res) => {
    await User.findByIdAndUpdate(
      req.user._id,
      {
        $set: {
          refreshToken: undefined,
        },
      },
      { new: true }
    )

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
    }

    return res
     .status(200)
     .clearCookie("accessToken", options)
     .clearCookie("refreshToken", options)
     .json(new ApiResponse(200, {}, "User logged out successfully"))
})

const refrehAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Refresh token is required");
  }

  try {
    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
    const user = await User.findById(decodedToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if(user?.refreshToken !== incomingRefreshToken) {
        throw new ApiError(401, "Invalid refresh token");
    }

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
    }

    const {accessToken, newRefreshToken: newRefreshToken} = await generateAccessAndRefreshToken(user._id);

    return res.status(200).cookie("accessToken", accessToken, options)
     .cookie("refreshToken", newRefreshToken, options)
     .json(
        new ApiResponse(
            200,
            {accessToken,
                refreshToken: newRefreshToken
            },
            "Access token refreshed successfully"
        )
     )

  } catch (error) {
    throw new ApiError(500, "Something went wrong while refreshing access token");
  }
});

const changeCurrentPassword = asyncHandler( async(req, res) => {
    const {oldPassword, newPassword} = req.body;

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPasswordCorrect) {
        throw new ApiError(401, "Invalid credentials");
    }

    user.password = newPassword;
    await user.save({ ValidateBeforeSave: false });

    return res.status(200)
     .json(new ApiResponse(200, {}, "password updated successfully"))
}); 

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req.user, "Current user deatils"));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const {fullname, email} = req.body;
    if(!fullname || !email) {
        throw new ApiError(400, "fullname and email are required");
    }

    const user = await User.findByIdAndUpdate(
      req.user?._id,
      { 
        $set: {
          fullname,
          email: email.toLowerCase(),
        },
      },
      { new: true }
    ).select("-password -refreshToken")

    return res.status(200).json(new ApiResponse(200, user, "Account updated Successfully"));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.files?.path;

    if(!avatarLocalPath) {
        throw new ApiError(400, "avatar file is missing");
    }
    const avatar = await uploadOnCloudinary(avatarLocalPath);
    if(!avatar.url) {
        throw new ApiError(500, "Error uploading avatar image");
    }

    const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          avatar: avatar.url,
        },
      },
      { new: true }
    ).select("-password -refreshToken")

    return res.status(200).json(new ApiResponse(200, user, "Avatar updated successfully"));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImagePath = req.file?.path;
    if(!coverImagePath){
        throw new ApiError(400, "cover image file is missing");
    }
    const coverImage = await uploadOnCloudinary(coverImagePath);

    if(!coverImage.url) {
        throw new ApiError(500, "Error uploading cover image");
    }

    const user = await User.findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          coverImage: coverImage.url,
        },
      },
      { new: true }
    ).select("-password -refreshToken")

    return res.status(200).json(new ApiResponse(200, user, "Cover image updated successfully"));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const {username} = req.params;
    if(!username?.trim){
        throw new ApiError(400, "Username is required");
    }

    const channel = await User.aggregate(
        [
            {
                $match: {
                    username: username.trim().toLowerCase()
                }
            },
            {
                $lookup: {
                    from: "subscriptions",
                    localField: "_id",
                    foreignField: "channel",
                    as: "subscribers"
                }
            },
            {
                 
            }
        ]
    )
});

export {
    registerUser, 
    loginUser, 
    refrehAccessToken, 
    logoutUser, 
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getCurrentUser,
    changeCurrentPassword,
    getUserChannelProfile
};