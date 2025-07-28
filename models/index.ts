import { Sequelize } from 'sequelize';
import DBService from '../database/DBService';

import { initSystemUserModel, SystemUser } from './SystemUser';
import { initUserRoleModel, UserRole } from './UserRole';
import { initRoleModel, Role } from './Role';
import { initPermissionModel, Permission } from './Permission';
import { initRolePermissionModel, RolePermission } from './RolePermission';
import { initSystemUserSecretModel, SystemUserSecret } from './SystemUserSecret';

const dbService = new DBService();
const sequelize = dbService.sequelizeWriter;

const db = {
    Sequelize,
    sequelize,
    SystemUser: initSystemUserModel(sequelize),
    UserRole: initUserRoleModel(sequelize),
    Role: initRoleModel(sequelize),
    Permission: initPermissionModel(sequelize),
    RolePermission: initRolePermissionModel(sequelize),
    SystemUserSecret: initSystemUserSecretModel(sequelize),
};

// 🧩 Associations
db.Role.belongsToMany(db.Permission, {
    through: db.RolePermission,
    foreignKey: 'role_id',
    otherKey: 'permission_id',
    as: 'permissions',
});

db.Permission.belongsToMany(db.Role, {
    through: db.RolePermission,
    foreignKey: 'permission_id',
    otherKey: 'role_id',
    as: 'roles',
});

db.SystemUser.belongsToMany(db.Role, {
    through: db.UserRole,
    foreignKey: 'system_user_id',
    otherKey: 'role_id',
    as: 'roles',
});

db.Role.belongsToMany(db.SystemUser, {
    through: db.UserRole,
    foreignKey: 'role_id',
    otherKey: 'system_user_id',
    as: 'users',
});

db.SystemUser.hasMany(db.SystemUserSecret, {
    foreignKey: 'user_id',
    as: 'secrets',
});

db.SystemUserSecret.belongsTo(db.SystemUser, {
    foreignKey: 'user_id',
    as: 'user',
});

export default db;
export { dbService };
