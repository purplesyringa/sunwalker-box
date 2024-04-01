all: renderer
	npx --prefix renderer -- renderer

clean:
	rm -r Rendered renderer

renderer:
	git clone https://github.com/yuki0iq/renderer
	git -C renderer reset --hard
	git -C renderer pull
	npm --prefix renderer install
