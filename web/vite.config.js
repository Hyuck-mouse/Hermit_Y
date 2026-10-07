import { fileURLToPath, URL } from 'node:url';
import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
export default defineConfig({
    plugins: [vue()],
    resolve: {
        alias: {
            '@': fileURLToPath(new URL('./src', import.meta.url)),
        },
    },
    server: {
        port: 5173,
        // /api/* → knowledge_service (127.0.0.1:8765)
        // /task-api/* → agent_service (127.0.0.1:8766)
        proxy: {
            '/api': {
                target: 'http://127.0.0.1:8765',
                changeOrigin: true,
                rewrite: function (p) { return p.replace(/^\/api/, ''); },
            },
            '/task-api': {
                target: 'http://127.0.0.1:8766',
                changeOrigin: true,
                rewrite: function (p) { return p.replace(/^\/task-api/, ''); },
            },
        },
    },
});
