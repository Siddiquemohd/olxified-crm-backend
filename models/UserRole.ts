import { Sequelize, DataTypes, Model } from 'sequelize';

export class UserRole extends Model {}

export const initUserRoleModel = (sequelize: Sequelize) => {
  UserRole.init({
    system_user_id: {
      type: DataTypes.UUID,
      primaryKey: true,
    },
    role_id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
    },
  }, {
    sequelize,
    modelName: 'UserRole',
    tableName: 'user_role',
    timestamps: false,
  });

  return UserRole;
};
