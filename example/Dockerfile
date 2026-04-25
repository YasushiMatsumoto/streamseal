FROM node:22-alpine
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY tsconfig*.json ./
COPY src/ src/
COPY example/browser-server.ts example/browser-server.ts
COPY example/browser/ example/browser/

# Build dist/ so the browser can load /dist/client/index.js
RUN npm run build

# example/keys/ and example/received/ are mounted as volumes at runtime
CMD ["node_modules/.bin/tsx", "example/browser-server.ts"]
