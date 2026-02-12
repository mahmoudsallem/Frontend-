FROM node:18-alpine AS build

WORKDIR /app

COPY package*.json ./
# Use npm ci for faster, reliable, deterministic builds
RUN npm ci

COPY . .
ARG GENERATE_SOURCEMAP=true
RUN GENERATE_SOURCEMAP=$GENERATE_SOURCEMAP npm run build

FROM nginx:alpine
# Remove default nginx static assets
RUN rm -rf /usr/share/nginx/html/*

COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget -q --spider http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]