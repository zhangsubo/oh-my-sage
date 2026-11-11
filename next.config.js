/** @type {import('next').NextConfig} */
const isDev = process.env.NODE_ENV !== 'production';

const cspDirectives = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

const nextConfig = {
  // 实验性功能
  experimental: {
    // Next.js 14 服务端外部包
    serverComponentsExternalPackages: ['ws', 'elliptic', 'bn.js'],
    // 启用服务器操作
    serverActions: {
      bodySizeLimit: '2mb',
    },
  },

  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Content-Security-Policy', value: cspDirectives },
        ],
      },
    ];
  },

  // Webpack 配置
  webpack: (config, { isServer }) => {
    if (!isServer) {
      // 客户端不包含这些模块
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
        ws: false,
      };
    }
    return config;
  },
};

module.exports = nextConfig;
