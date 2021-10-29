hashlenghts = ['224', '256', '384', '512']

rsp_file_templates = [
    'shabytetestvectors/SHA{}ShortMsg.rsp',
    'shabytetestvectors/SHA{}LongMsg.rsp',
]

for hashlenght in hashlenghts:

    out_filename = 'sha{}_input.txt'.format(hashlenght)
    out_file = open(out_filename, 'w')
    vectors = 0

    for rsp_file_template in rsp_file_templates:
        rsp_file = rsp_file_template.format(hashlenght)

        lines = open(rsp_file).readlines()

        #parse into individual records
        length, msg, md = None, None, None
        seed = None
        for line in lines:
            # Handle ShortMsg and LongMsg type of files
            if line.startswith('Len'):
                length = int(line.split(' = ')[1])

            if line.startswith('Msg ='):
                msg = line.split(' = ')[1].strip()
                # empty message in shabytetestvectors are marked as 00 (for ini format compatibility)
                # we must ignore that because we know lenght is 0
                if length == 0: 
                    msg = ''

            if line.startswith('MD ='):
                md = line.split(' = ')[1].strip()

            if length is not None and msg is not None and md is not None:
                out_file.write(msg + '\n' + md + '\n')
                length, msg, md = None, None, None
                vectors += 1

    out_file.close()
    print('"{}" with {} test vectors generated.'.format(out_filename, vectors))
