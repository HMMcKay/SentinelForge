# syntax=docker/dockerfile:1.7
FROM node:24.18.0-alpine3.23 AS deps
WORKDIR /app
ENV npm_config_update_notifier=false \
    npm_config_fund=false \
    npm_config_audit=false
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts

FROM deps AS build
COPY tsconfig.json tsconfig.app.json tsconfig.node.json vite.config.ts vitest.config.ts ./
COPY index.html ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM deps AS test
COPY . .
CMD ["npm", "test"]

FROM nginxinc/nginx-unprivileged:1.30.2-alpine3.23@sha256:de3e40ec8b7debd7194fc798d4bbfb102c7f8b012b2c73032816b5f72393acdd AS runtime
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:8080/healthz || exit 1
