test:
	@btest -c btest.cfg -j -f diag.log

zam:
	@btest -c btest.cfg -j -a zam -f diag.log

coverage:
	@rm -rf .tmp
	@btest -c btest.cfg -j -a coverage -f diag.log
	@./Scripts/summarize-coverage.sh

clean:
	rm -rf .tmp diag.log
