FROM node:20-alpine
WORKDIR /app
COPY package.json server.js ./
ENV PORT=8080 DATA_DIR=/data
RUN mkdir -p /data
EXPOSE 8080
CMD ["node", "server.js"]
