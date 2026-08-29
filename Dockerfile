FROM node:22-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S centinell && adduser -S centinell -G centinell
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=centinell:centinell . .
USER centinell
EXPOSE 3000
CMD ["node","src/server.js"]
