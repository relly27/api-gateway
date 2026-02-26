module.exports = {
  apps : [{
    name        : 'sc-backend-api',
    script      : 'src/app.js',
    instances   : 'max',
    exec_mode   : 'cluster',
    autorestart : true,
    watch       : false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'development',
    },
    env_production: {
      NODE_ENV: 'production',
    },
    env_testing: {
      NODE_ENV: 'testing',
    }
  }]
};
