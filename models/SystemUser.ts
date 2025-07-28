import { Sequelize, DataTypes, Model, UUIDV4 } from 'sequelize';

export class SystemUser extends Model {}

export const initSystemUserModel = (sequelize: Sequelize) => {
  SystemUser.init({
    id: {
      type: DataTypes.UUID,
      defaultValue: UUIDV4,
      primaryKey: true,
    },
    name: DataTypes.STRING,
    mobile_number: DataTypes.STRING,
    email: DataTypes.STRING,
    password: DataTypes.STRING,
    created_at: DataTypes.DATE,
    updated_at: DataTypes.DATE,
    totp_secret: DataTypes.STRING,
    deleted_at: DataTypes.DATE,
  }, {
    sequelize,
    modelName: 'SystemUser',
    tableName: 'system_users',
    timestamps: false,
  });

  return SystemUser;
};
