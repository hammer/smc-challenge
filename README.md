Data
====
You can obtain the truth VCF from https://www.synapse.org/#!Synapse:syn2335185.
To generate the compressed VCF file and its index:
```
$ bgzip -c data/truth.chr20.vcf > data/truth.chr20.vcf.gz
$ tabix -p vcf ../data/truth.chr20.vcf.gz
```

Scripts
=======
evaluator.py copied from https://github.com/adamewing/bamsurgeon/blob/master/etc/evaluator.py.
Example invocation:
```
$ ./scripts/evaluator.py -v data/truth.chr20.minus5plus2.vcf -t data/truth.chr20.vcf.gz -m SNV
tpcount, fpcount, subrecs, trurecs:
1440 2 1442 1445
```
