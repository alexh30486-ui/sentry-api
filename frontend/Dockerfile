# --- Dev stage: fast iteration with Vite's dev server + HMR ---
FROM node:20-alpine AS dev

WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev"]

# --- Build stage: static production bundle ---
FROM node:20-alpine AS build

WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

# --- Production stage: serve static bundle with a tiny web server ---
FROM node:20-alpine AS production

WORKDIR /app
RUN npm install -g serve
COPY --from=build /app/dist ./dist

EXPOSE 4173
CMD ["serve", "-s", "dist", "-l", "4173"]
