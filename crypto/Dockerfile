FROM python:3

# set a directory for the app
WORKDIR /usr/src/crypto
# copy all the files to the container
COPY . .

# install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# tell the port number the container should expose
EXPOSE 7777

# run the command
CMD ["python", "./crypto.py"]