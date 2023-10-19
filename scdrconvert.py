import csv
import os
import socket
import datetime
import shutil

# Dictionary to map sub-tags to their names
sub_tag_names = {
    0x80: "recordType",
    0x81: "networkInitiation",
    0x83: "servedIMSI",
    0x84: "servedIMEI",
    0xA5: "sgsnAddress",
    0x86: "msNetworkCapability",
    0x87: "routingArea",
    0x88: "locationAreaCode",
    0x89: "cellIdentifier",
    0x8A: "chargingID",
    0xAB: "ggsnAddressUsed",
    0x8C: "accessPointNameNI",
    0x8D: "pdpType",
    0xAE: "servedPDPAddress",
    0xAF: "listOfTrafficVolumes",
    0x90: "recordOpeningTime",
    0x91: "duration",
    0x92: "sgsnChange",
    0x93: "causeForRecClosing",
    0x95: "recordSequenceNumber",
    0xB4: "diagnostics",
    0xB5: "recSequenceNumList",
    0x96: "nodeID",
    0xB7: "recordExtensions",
    0x98: "localSequenceNumberList",
    0x99: "apnSelectionMode",
    0x9A: "accessPointNameOI",
    0x9B: "servedMSISDN",
    0x9C: "chargingCharacteristics",
    0x9D: "rATType",
    0xBE: "cAMELInformationPDP",
    0xBF1F: "rNCUnsentDownlinkVolumeList",
    0x9F20: "chChSelectionMode",
    0x9F21: "dynamicAddressFlag",
    0x9F22: "iMSIunauthenticatedFlag",
    0xBF23: "userCSGInformation",
    0xBF24: "servedPDPPDNAddressExt",
    0x9F28: "sgsnPLMNIdentifier",
    0x9F32: "consolidationResult",
}

listoftrafficvolumesTags = {
    0x81: "qosRequested",
    0x82: "qosNegotiated",
    0x83: "datavolumeGPRSUplink",
    0x84: "datavolumeGPRSDownlink",
    0x85: "changeCondition",
    0x86: "changeTime",
                         
}

# Initialize the order of sub-values for the output record
output_order = [
    'recordType', 'servedIMSI', 'sgsnAddress', 'routingArea', 'locationAreaCode',
    'cellIdentifier', 'chargingID', 'ggsnAddressUsed', 'accessPointNameNI', 'pdpType',
    'dynamicAddressFlag', 'DataVolumeGPRSUplink', 'DataVolumeGPRSDownlink', 'RESERVE1',
    'qoSNegotiated', 'qoSRequested', 'RecordOpeningDate', 'RecordOpeningTime1', 'duration',
    'accessPointNameOI', 'servedMSISDN'
]

# Define the log directory path in the current directory
log_directory = os.path.join(os.getcwd(), "log")

# Define the CDR output directory path in the current directory
csv_directory = os.path.join(os.getcwd(), "csv")

# Define the processed CDR  directory path in the current directory
processed_directory = os.path.join(os.getcwd(), "processed")

# Create the log directory if it doesn't exist
os.makedirs(log_directory, exist_ok=True)

# Create the log directory if it doesn't exist
os.makedirs(csv_directory, exist_ok=True)

# Create the processed directory if it doesn't exist
os.makedirs(processed_directory, exist_ok=True)

# Get the current date and time
current_datetime = datetime.datetime.now()
date = current_datetime.date()
time = current_datetime.strftime('%H-%M-%S')  # Format time as HH-MM-SS

# Create the log file path with the date and time in the filename
log_file_name = f"Conversionlog{date}_{time}.log"
log_file_path = os.path.join(log_directory, log_file_name)

def read_tlv_record(file):
    records = []
    try:
        while True:
            # Read the first byte (Start Byte)
            start_byte = int.from_bytes(file.read(1), byteorder='big')
            if not start_byte:
                break  # Reached the end of the file

            if start_byte != 0xB4:
                # If the first byte is not 0xB4, it's an invalid record
                raise ValueError(f"Invalid start byte: {start_byte}")

            # Read the second byte (Length Indicator)
            length_indicator = int.from_bytes(file.read(1), byteorder='big')

            # Determine the length based on the length indicator
            if length_indicator == 0x81:
                # If the second byte is 0x81, read the third byte as the length
                length = int.from_bytes(file.read(1), byteorder='big')
            elif length_indicator == 0x82:
                # If the second byte is 0x82, read the next two bytes as the length
                length_bytes = file.read(2)
                length = int.from_bytes(length_bytes, byteorder='big')
            else:
                # Invalid length indicator
                raise ValueError(f"Invalid length indicator: {length_indicator}")

            # Read the Value based on the determined length as binary data
            value = file.read(length)

            # Append the record to the list
            records.append((start_byte, value))

    except Exception as e:
        print(f"An error occurred: {e}")

    return records

def parse_sub_record(sub_record_bytes):
    sub_records = []
    i = 0
    while i < len(sub_record_bytes):
        tag_byte = sub_record_bytes[i]
        i += 1

        if tag_byte == 0x9F or tag_byte == 0xBF:
            # Two-byte tag
            tag_byte = (tag_byte << 8) | sub_record_bytes[i]
            i += 1

        length = sub_record_bytes[i]
        i += 1

        sub_value = sub_record_bytes[i:i + length]
        i += length

        sub_records.append((tag_byte, sub_value))

    return sub_records

# Function to convert TBCD bytes to a normal string
def convert_tbcd_to_string(tbcd_bytes):
    # Assuming each TBCD digit is represented as a nibble (4 bits)
    tbcd_string = ""
    for byte in tbcd_bytes:
        high_nibble = (byte >> 4) & 0x0F
        low_nibble = byte & 0x0F
        tbcd_string += str(low_nibble)
        tbcd_string += str(high_nibble)
    return tbcd_string

# Function to convert IP address bytes to a decimal IP address string
def convert_ip_address(ip_bytes):
    ip_address = ".".join(str(byte) for byte in ip_bytes)
    return ip_address

# Function to convert APN bytes to ASCII characters
def convert_apn(apn_bytes):
    apn = apn_bytes.decode('ascii')
    return apn

# Function to convert the duration sub-tag value to decimal
def convert_duration(duration_bytes):
    # Assuming duration_bytes is a big-endian 32-bit integer
    duration = int.from_bytes(duration_bytes, byteorder='big')
    return str(duration)

def convert_listoftrafficvolumes(trafficvolumebytes):
    qos_requested = None
    qos_negotiated = None
    gprs_uplink_total = 0
    gprs_downlink_total = 0
    changeofchar_index = 1  # Initialize the ChangeofChar index

    while len(trafficvolumebytes) >= 3 and trafficvolumebytes[0] == 0x30:
        # Read the ChangeofCharCondition length from the second byte
        changeofcharcondition_length = trafficvolumebytes[1]

        # Check if there are enough bytes to read the entire ChangeofCharCondition
        if len(trafficvolumebytes) >= 2 + changeofcharcondition_length:
            # Extract the ChangeofCharCondition value
            changeofcharcondition_value = trafficvolumebytes[2:2 + changeofcharcondition_length]

            i = 0
            while i < len(changeofcharcondition_value):
                # Read the tag and length
                tag = changeofcharcondition_value[i]
                length = changeofcharcondition_value[i + 1]

                # Extract the value bytes
                value = changeofcharcondition_value[i + 2:i + 2 + length]

                if tag == 0x81:  # qosRequested
                    qos_requested = ''.join(nibble for byte in value for nibble in f'{byte:02X}')
                elif tag == 0x82:  # qosNegotiated
                    qos_negotiated = ''.join(nibble for byte in value for nibble in f'{byte:02X}')
                elif tag == 0x83:  # datavolumeGPRSUplink
                    gprs_uplink_total += int.from_bytes(value, byteorder='big')
                elif tag == 0x84:  # datavolumeGPRSDownlink
                    gprs_downlink_total += int.from_bytes(value, byteorder='big')

                # Move the index to the next TLV
                i += 2 + length

            # Increment the ChangeofChar index
            changeofchar_index += 1

            # Remove the processed ChangeofCharCondition from the byte array
            trafficvolumebytes = trafficvolumebytes[2 + changeofcharcondition_length:]
        else:
            # If there are not enough bytes to read the full ChangeofCharCondition, exit the loop
            break

    # Return the accumulated values
    result = {}
    if qos_requested is not None:
        result['qoSRequested'] = qos_requested
    if qos_negotiated is not None:
        result['qoSNegotiated'] = qos_negotiated
    result['DataVolumeGPRSUplink'] = str(gprs_uplink_total)
    result['DataVolumeGPRSDownlink'] =str(gprs_downlink_total)

    return result


        
      

def convert_recordopeningtime(sub_value):
    if len(sub_value) >= 6:
        # Extract the date (first 3 bytes) and time (next 3 bytes) from sub_value
        date_bytes = sub_value[:3]
        time_bytes = sub_value[3:6]

        # Convert date_bytes to "YYYYMMDD" format
        year = ''.join([str((date_bytes[0] >> 4) & 0xF), str(date_bytes[0] & 0xF)])
        month = ''.join([str((date_bytes[1] >> 4) & 0xF), str(date_bytes[1] & 0xF)])
        day = ''.join([str((date_bytes[2] >> 4) & 0xF), str(date_bytes[2] & 0xF)])
        date_str = f"20{year}{month}{day}"  # Assuming 'YY' represents a year in the 21st century

        # Convert time_bytes to "HHMMSS" format
        hour = ''.join([str((time_bytes[0] >> 4) & 0xF), str(time_bytes[0] & 0xF)])
        minute = ''.join([str((time_bytes[1] >> 4) & 0xF), str(time_bytes[1] & 0xF)])
        second = ''.join([str((time_bytes[2] >> 4) & 0xF), str(time_bytes[2] & 0xF)])
        time_str = f"{hour}{minute}{second}"

        result_str = {}
        # Create the concatenated string
        result_str['RecordOpeningDate'] = date_str
        result_str['RecordOpeningTime1'] = time_str
        return result_str
    else:
        # Handle the case where the sub_value doesn't have enough bytes
        return "Invalid sub_value (insufficient bytes)"





# Get a list of all .dat files in the current directory
dat_files = [f for f in os.listdir('.') if f.endswith('.dat')]

for dat_file in dat_files:
    # Specify the input file path (current .dat file)
    input_file_path = dat_file



    # Specify the output CSV file path (using the same name with .csv extension)
    csv_file_name = os.path.splitext(dat_file)[0] + '.csv'
    csv_file_path=  os.path.join(csv_directory, csv_file_name)

    # Open the input file in binary read mode
    with open(input_file_path, 'rb') as input_file:
        # Read the TLV records from the input file
        records = read_tlv_record(input_file)
        shutil.move(input_file_path, processed_directory)

  # Open the output CSV file for writing
    with open(csv_file_path, 'w', newline='') as output_csv_file:
        csv_writer = csv.writer(output_csv_file, delimiter='|')

        # Process each TLV record and its sub-records and write them to the CSV file
        for record in records:
            # The first byte of the record is the Tag
            tag = record[0]

            # The remaining bytes of the record are the Value
            value = record[1]
            sub_records = parse_sub_record(value)
            # Create a list to store the values of sub-records within the record
            sub_record_values = []
            
            #lastadd
            sub_record_values_dict = {}

            for sub_tag, sub_value in sub_records:
                # Convert sub-values of specific tags to strings
                if sub_tag == 0x83:
                    sub_value = convert_tbcd_to_string(sub_value)
                elif sub_tag == 0x9B:
                    sub_value = convert_tbcd_to_string(sub_value)
                elif sub_tag == 0x84:
                    sub_value = convert_tbcd_to_string(sub_value)
                elif sub_tag == 0xA5:  # sgsnAddress tag
                    ip_length = sub_value[1]
                    ip_bytes = sub_value[2:2 + ip_length]
                    sub_value = convert_ip_address(ip_bytes)
                elif sub_tag == 0xAB:  # ggsnAddressUsed tag
                    ip_length = sub_value[1]
                    ip_bytes = sub_value[2:2 + ip_length]
                    sub_value = convert_ip_address(ip_bytes)
                elif sub_tag == 0x8C:  # accessPointNameNI tag
                    sub_value = convert_apn(sub_value)
                elif sub_tag == 0x9A:  # accessPointNameOI tag
                    sub_value = convert_apn(sub_value)
                elif sub_tag == 0x91:  # duration tag
                    sub_value = convert_duration(sub_value)
                elif sub_tag == 0xAF:  # listoftrafficvolumes tag
                    sub_value = convert_listoftrafficvolumes(sub_value)
                elif sub_tag == 0x90:  # recordopeningtime tag
                    sub_value = convert_recordopeningtime(sub_value)
                else:
                    sub_value = convert_duration(sub_value)
            
                
              # Append the sub-record values to the list
                if sub_tag == 0x90:
                    sub_record_values.append(f"{sub_value}")
                    #print(f"{sub_value}")

                elif sub_tag == 0xAF:
                  sub_record_values.append(f"{sub_value}")
                  #print(f"{sub_value}")

                else:
                  sub_record_values.append(f"{sub_tag}: {sub_value}")


                if sub_tag == 0x90 or sub_tag == 0xAF:
                    # Assuming sub_value is a dictionary
                    sub_record_values_dict.update(sub_value)


                else:
                  # Get the sub-tag name from the dictionary or use the hex value
                  sub_tag_name = sub_tag_names.get(sub_tag, f"0x{sub_tag:02X}")
                  #print(sub_tag_name)
                  #lastadd
                  sub_record_values_dict[sub_tag_name] = sub_value
                  #print(sub_record_values_dict[sub_tag_name])
                
            
            #print(sub_record_values_dict) 
            #lastadd
            ordered_sub_record_values = [sub_record_values_dict.get(key, '') for key in output_order]


            # Join the sub-record values into a single string, separated by commas
            #lastadd
            #sub_record_values_str = ', '.join(sub_record_values)
            sub_record_values_str = '|'.join(ordered_sub_record_values)

            sub_record_values_list = sub_record_values_str.split('|')

            if len(sub_record_values_list) >= 2 and not sub_record_values_list[1].startswith('62'):
              # The second field does not start with '62 .i.e. its a roaming IMSI'
              # You can add your code here for this condition
              # Write the Tag and the concatenated sub-record values to the CSV file on a single line
              #csv_writer.writerow([f"0x{tag:02X}", sub_record_values_str])
              csv_writer.writerow( [sub_record_values_str])

    
    # Create the log message
    log_message = f"{date},{time} Conversion of {dat_file} complete. Results saved in {csv_file_path}\n"
    # Write the log message to the log file
    with open(log_file_path, 'a') as log_file:
      log_file.write(log_message)
    print(f"Conversion of {dat_file} complete. Results saved in {csv_file_path}")