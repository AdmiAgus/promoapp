const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();

// 1. Proxy para Autenticación (/auth/)
app.use('/auth/', createProxyMiddleware({ 
    target: 'http://192.168.68.141:9000', 
    changeOrigin: true 
}));

// 2. Proxy para API (/api/)
// pathRewrite quita el prefijo /api para que el backend reciba la ruta limpia [cite: 92, 93]
app.use('/api/', createProxyMiddleware({ 
    target: 'http://192.168.68.141:9000', 
    changeOrigin: true,
    pathRewrite: { '^/api': '' } 
}));

// 3. Servir archivos estáticos de la App de Promotores
// Importante: express.static debe ir ANTES del manejador de rutas de abajo [cite: 93]
app.use('/promotores', express.static(path.join(__dirname, 'promotores')));

// 4. Manejo de Rutas para PWA/SPA (SOLUCIÓN DEFINITIVA)
// Usamos una Regex pura /^\/promotores\/.*$/ para capturar todo 
// Esto evita el error "Missing parameter name" de path-to-regexp [cite: 93, 94, 96]
app.get(/^\/promotores\/.*$/, (req, res) => {
    res.sendFile(path.join(__dirname, 'promotores', 'index.html'));
});

// 5. App Principal
// app.get('/', (req, res) => {
//     res.send('Servidor centralizado activo. Accede a /promotores para entrar a la app.');
// });

// Escuchar en el puerto 80
const PORT = 3050;
app.listen(PORT, () => {
    console.log(`\n🚀 Servidor corriendo en el puerto ${PORT}`);
    console.log(`✅ App de promotores: http://localhost/promotores`);
    console.log(`✅ Proxy API: http://localhost/api -> puerto 9000`);
});
