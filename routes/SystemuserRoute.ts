import express from "express";
import SytemuserController from "../controllers/CompressCrmController";
import { SystemuserRouter } from ".";

const SytemuserRouter = express.Router();
const sytemuserController = new SytemuserController();


//SystemUser  Routes

SytemuserRouter.route("/login").post(sytemuserController.authLogin);
SytemuserRouter.route("/register").post(sytemuserController.createUser);
SytemuserRouter.route("/generateqrcode").post(sytemuserController.generateQRCode);
SytemuserRouter.route("/getuser").get(sytemuserController.getUserDetails);
SytemuserRouter.route("/getalluser").get(sytemuserController.getAllUsers);
SytemuserRouter.route("/getroles").get(sytemuserController.getRoles);
SytemuserRouter.route("/updateuser").post(sytemuserController.UpdateUser);
SytemuserRouter.route("/deleteuser").post(sytemuserController.deleteUser);
SytemuserRouter.route("/logout").post(sytemuserController.logout);
SytemuserRouter.route("/verifytotp").post(sytemuserController.verifyTOTP);
SytemuserRouter.route("/fetchsecret").post(sytemuserController.fetchSecretKey);
SytemuserRouter.route("/deletesecert").post(sytemuserController.deleteSecretKey);
SytemuserRouter.route("/resetpassword").post(sytemuserController.resetPassword);
SytemuserRouter.route("/loguseractivity").post(sytemuserController.logUserActivity);
SytemuserRouter.route("/getallactivites").get(sytemuserController.getAllUserActivities);
SytemuserRouter.route("/getallusername").get(sytemuserController.getAllUserNamesAndUUIDs);
SytemuserRouter.route("/filteruseractivites").post(sytemuserController.filterUserActivities);
SytemuserRouter.route("/getalldeleteduser").get(sytemuserController.getAllDeletedUsers);
SytemuserRouter.route("/createcategory").post(sytemuserController.CreateCategory);
SytemuserRouter.route("/getallcategories").get(sytemuserController.getAllCategories);
SytemuserRouter.route("/updatecategory").post(sytemuserController.updateCategory);
SytemuserRouter.route("/deletecategory").post(sytemuserController.deleteCategory);
SytemuserRouter.route("/createsubcategory").post(sytemuserController.createSubCategory);
SytemuserRouter.route("/getallsubcategories").get(sytemuserController.getAllSubCategories);
SytemuserRouter.route("/updatesubcategory").post(sytemuserController.updateSubCategory);
SytemuserRouter.route("/deletesubcategory").post(sytemuserController.deleteSubCategory);
export default SytemuserRouter;
