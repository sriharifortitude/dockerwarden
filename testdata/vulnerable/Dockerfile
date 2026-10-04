FROM node
ARG NPM_TOKEN=changeme
ENV DB_PASSWORD=hunter2
RUN apt-get update
RUN apt-get install -y curl build-essential
RUN curl -fsSL https://example.com/install.sh | sh
ADD https://example.com/tool.tar.gz /opt/tool.tar.gz
COPY .env /app/.env
COPY package.json /app/
RUN chmod -R 777 /app && sudo npm install
EXPOSE 22 3000
CMD ["node", "server.js"]
