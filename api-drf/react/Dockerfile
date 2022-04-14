FROM node:14-alpine

WORKDIR /app
COPY package.json /app/package.json
#COPY package-lock.json /app/package-lock.json
RUN npm i && \
    npm i @coreui/coreui-pro @types/react @types/react-router-dom \
          @types/react-redux @types/react-dom react-redux && \
    npm audit fix
