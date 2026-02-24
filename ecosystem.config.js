module.exports = {
    apps: [
        {
            name: 'ids-api',
            script: 'server.js',
            cwd: './dashboard/backend',
            env: {
                NODE_ENV: 'production',
                PORT: 3000
            },
            // Restart if memory exceeds 200MB
            max_memory_restart: '200M',
            // Restart on failure with exponential backoff
            exp_backoff_restart_delay: 100,
            // Logging
            error_file: './logs/ids-api-error.log',
            out_file: './logs/ids-api-out.log',
            merge_logs: true,
            log_date_format: 'YYYY-MM-DD HH:mm:ss'
        },
        {
            name: 'mini-ids',
            script: './mini_ids',
            cwd: './',
            // The C++ binary is not a Node script
            interpreter: 'none',
            // Restart if it crashes
            autorestart: true,
            exp_backoff_restart_delay: 100,
            // Logging
            error_file: './logs/mini-ids-error.log',
            out_file: './logs/mini-ids-out.log',
            merge_logs: true,
            log_date_format: 'YYYY-MM-DD HH:mm:ss'
        }
    ]
};
