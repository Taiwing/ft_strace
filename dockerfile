FROM gcc:13.1
COPY . /app
WORKDIR /app/
RUN make
CMD ["bash"]
