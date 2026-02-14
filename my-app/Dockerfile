# ── 1. 依存パッケージのインストール ──────────────────────
FROM node:22-alpine AS deps
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

# ── 2. ビルド ─────────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN npm run build

# ── 3. 本番実行 (standalone) ──────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# standalone サーバー本体
COPY --from=builder /app/.next/standalone ./
# 静的アセット
COPY --from=builder /app/.next/static ./.next/static
# public フォルダ
COPY --from=builder /app/public ./public

EXPOSE 3000

CMD ["node", "server.js"]
