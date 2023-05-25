FROM python:3.10.11

WORKDIR /site-project
COPY . /site-project
RUN pip install --trusted-host pypi.python.org -r requirements.txt

EXPOSE 5000

ENV NAME flask-app

CMD ["flask", "run", "--host=0.0.0.0"]