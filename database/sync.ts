import db, { dbService } from '../models';

async function syncDatabase() {
  try {
    await dbService.testConnections();
    await db.sequelize.sync({ alter: false });

    console.log('✅ Model sync complete');

    await seedInitialData();

    console.log('✅ Seeding complete');
  } catch (error) {
    console.error('❌ Database sync failed:', error);
    process.exit(1);
  }
}

async function seedInitialData() {
  // Seed roles
  await db.Role.bulkCreate(
    [{ id: 1, name: 'Admin', level: 1 }],
    { ignoreDuplicates: true }
  );

  // Seed permissions
  await db.Permission.bulkCreate([
    { id: 1, name: 'customer.view', description: 'can view customer' },
    { id: 2, name: 'customer.add', description: 'can add customer' },
    { id: 3, name: 'customer.delete', description: 'can delete customer' },
    { id: 4, name: 'customer.edit', description: 'can edit customer' },
    { id: 5, name: 'customer.audit', description: 'can audit customer' },
    { id: 7, name: 'systemuser.view', description: 'can view systemuser' },
    { id: 8, name: 'systemuser.add', description: 'can add systemuser' },
    { id: 9, name: 'systemuser.delete', description: 'can delete systemuser' },
    { id: 10, name: 'systemuser.edit', description: 'can edit systemuser' },
    { id: 11, name: 'systemuser.audit', description: 'can audit systemuser' },
    { id: 12, name: 'useractivity.view', description: 'can view useractivities' },
  ], { ignoreDuplicates: true });

  // Seed role-permissions
  await db.RolePermission.bulkCreate([
    { role_id: 1, permission_id: 1 },
    { role_id: 1, permission_id: 2 },
    { role_id: 1, permission_id: 3 },
    { role_id: 1, permission_id: 4 },
    { role_id: 1, permission_id: 5 },
    { role_id: 1, permission_id: 7 },
    { role_id: 1, permission_id: 8 },
    { role_id: 1, permission_id: 9 },
    { role_id: 1, permission_id: 10 },
    { role_id: 1, permission_id: 11 },
    { role_id: 1, permission_id: 12 },
  ], { ignoreDuplicates: true });
}

syncDatabase();
