const db = require('../db');

const checkDepartment = async (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const departmentResult = await db.query(
      `SELECT d.id, d.name
       FROM departments d
       JOIN user_departments ud ON d.id = ud.department_id
       WHERE ud.user_id = $1`,
      [req.user.userId]
    );

    req.user.departments = departmentResult.rows.map(d => d.id);
    req.user.departmentNames = departmentResult.rows.map(d => d.name);

    // If request contains a department context (e.g. /dept/:deptId/...), verify access
    const deptIdInUrl = req.params.deptId || req.query.deptId;
    if (deptIdInUrl && !req.user.departments.includes(parseInt(deptIdInUrl))) {
      // Allow admin to bypass
      const adminResult = await db.query(
        `SELECT r.name FROM roles r JOIN user_roles ur ON r.id = ur.role_id WHERE ur.user_id = $1 AND r.name = 'admin'`,
        [req.user.userId]
      );
      if (adminResult.rows.length === 0) {
        return res.status(403).json({ error: 'Forbidden: You do not belong to this department' });
      }
    }

    next();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = checkDepartment;
