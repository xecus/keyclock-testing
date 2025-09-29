FROM node:22-alpine

WORKDIR /app/my-app

CMD [ "npm", "run", "dev" ]