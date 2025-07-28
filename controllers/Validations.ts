import * as Yup from "yup";

// Define Yup schema for the new fields
export const createUserSchema = Yup.object().shape({
  name: Yup.string().required("Name is required"),
  mobile_number: Yup.string()
    .matches(/^\+\d{1,3}\d{10}$/, "Mobile number must include country code and be in the format +<country_code><number>")
    .required("Mobile number is required"),
  email: Yup.string().email("Invalid email format").required("Email is required"),
  password: Yup.string().min(6, "Password must be at least 6 characters").required("Password is required"),
  roleLevel: Yup.number().required("Role level is required"),
});
// Define Yup schema for login user 
export const loginSchema = Yup.object().shape({
  email: Yup.string().email().required(),
  password: Yup.string().required(),
});
// Define Yup schema for userId
export const getUserDetailsSchema = Yup.object({
  id: Yup.string().required("User ID is required"),
});
// Define Yup schema for updating user details
export const updateUserSchema = Yup.object({
  name: Yup.string().optional(),
  mobile_number: Yup.string(),
  email: Yup.string().email("Invalid email format"),

});
// Define Yup schema for getalluser details
export const getAllUsersSchema = Yup.object().shape({
  page: Yup.number().min(1).default(1), // Optional pagination, defaulting to page 1
  pageSize: Yup.number().min(1).max(100).default(10), // Optional page size, defaulting to 10
});
// Define Yup schema for delete user
export const deleteUserSchema = Yup.object().shape({
  id: Yup.string().required("User ID is required"),
});
// Define Yup schema for verifytotp 
export const verifytotpSchema = Yup.object().shape({
  token: Yup.string().required("token is required"),
  secretKey: Yup.string().required("SecretKey is required"),
  userId: Yup.string().required("userId is required"),
});
// Define Yup schema for fetchsecretkey 
export const fetchsecretkeySchema = Yup.object().shape({
  userId: Yup.string().required("userId is required"),
});
// Define Yup schema for deletesecretkey 
export const deletesecretkeySchema = Yup.object().shape({
  userId: Yup.string().required("userId is required"),
});
// Define Yup schema for resetpassoerd 
export const resetPasswordSchema = Yup.object().shape({
  email: Yup.string().email("Invalid email format").optional(),
  mobile_number: Yup.string()
    .optional(),
  new_password: Yup.string()
    .min(6, "Password must be at least 6 characters")
    .max(20, "Password must be at most 20 characters")
    .notOneOf(
      ["123456", "password", "12345678", "qwerty", "abc123"],
      "Weak password is not allowed"
    )
    .required("New password is required"),
});
export const logUserActivitySchema = Yup.object().shape({
  userId: Yup.string().required("User ID is required"),
  userActivity: Yup.string().required("userActivity is required"),
  module: Yup.string().required("Module is required"),  // Ensure module is required
  type: Yup.string().required("Type is required"),      // Ensure type is required
});

export const filteruseractivitySchema = Yup.object({
  uuId: Yup.string(),
  userActivity: Yup.string(),
  startDate: Yup.date().typeError('startDate must be a valid date (YYYY-MM-DD format)'),
  endDate: Yup.date().typeError('endDate must be a valid date (YYYY-MM-DD format)'),
  module: Yup.string(),
  type: Yup.string(),
}).test(
  'at-least-one-field',
  'At least one filter field is required',
  (value) => !!Object.values(value).filter((v) => v !== undefined && v !== '').length
);
