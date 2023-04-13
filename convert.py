input_file = "gfwlist.txt"  # 您的原始文本文件
output_file = "gfwlist_out.txt"  # 新的输出文件

with open(input_file, "r") as infile, open(output_file, "w") as outfile:
    for line in infile:
        line = line.strip().replace('"', '').replace(',', '')
        outfile.write(line + "\n")
