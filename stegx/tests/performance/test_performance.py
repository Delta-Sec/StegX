#!/usr/bin/env python3
import os
import time
import pytest
import tempfile
import numpy as np
from PIL import Image
import matplotlib.pyplot as plt

from stegx import perform_encode, perform_decode


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield tmpdirname

@pytest.fixture
def create_test_file():

    def _create_file(directory, size_kb):

        file_path = os.path.join(directory, f"test_file_{size_kb}kb.bin")
        data = os.urandom(size_kb * 1024)
        with open(file_path, "wb") as f:
            f.write(data)
        return file_path
    
    return _create_file

@pytest.fixture
def create_test_image():

    def _create_image(directory, width, height, mode="RGB"):

        file_path = os.path.join(directory, f"test_image_{width}x{height}_{mode}.png")
        
        if mode == "RGB":
            img_array = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
            img = Image.fromarray(img_array, mode)
        elif mode == "RGBA":
            img_array = np.random.randint(0, 256, (height, width, 4), dtype=np.uint8)
            img = Image.fromarray(img_array, mode)
        elif mode == "L":
            img_array = np.random.randint(0, 256, (height, width), dtype=np.uint8)
            img = Image.fromarray(img_array, mode)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        
        img.save(file_path)
        return file_path
    
    return _create_image

@pytest.mark.performance
def test_encode_performance_file_size(temp_dir, create_test_file, create_test_image):

    global time
    image_path = create_test_image(temp_dir, 1000, 1000)

    file_sizes = [10, 50, 100, 200, 500]
    encode_times = []
    
    password = "StegXTestPassword123!@#"
    
    for size in file_sizes:
        file_path = create_test_file(temp_dir, size)
        output_path = os.path.join(temp_dir, f"stego_output_{size}kb.png")

        start_time = time.time()
        success = perform_encode(image_path, file_path, output_path, password, compress=True)
        end_time = time.time()
        
        if success:
            encode_time = end_time - start_time
            encode_times.append(encode_time)
            print(f"File size: {size} KB, Encode time: {encode_time:.4f} seconds")
        else:
            print(f"Encoding failed for file size: {size} KB")
            encode_times.append(None)

    report_path = os.path.join(temp_dir, "file_size_performance.png")

    valid_sizes = [size for size, time in zip(file_sizes, encode_times) if time is not None]
    valid_times = [time for time in encode_times if time is not None]
    
    if valid_sizes and valid_times:
        plt.figure(figsize=(10, 6))
        plt.plot(valid_sizes, valid_times, marker='o')
        plt.title('StegX Encoding Performance vs File Size')
        plt.xlabel('File Size (KB)')
        plt.ylabel('Encoding Time (seconds)')
        plt.grid(True)
        plt.savefig(report_path)
        print(f"Performance report saved to: {report_path}")

@pytest.mark.performance
def test_encode_performance_image_size(temp_dir, create_test_file, create_test_image):

    global time
    file_path = create_test_file(temp_dir, 100)

    image_sizes = [(500, 500), (1000, 1000), (1500, 1500), (2000, 2000)]
    encode_times = []
    
    password = "StegXTestPassword123!@#"
    
    for width, height in image_sizes:
        image_path = create_test_image(temp_dir, width, height)
        output_path = os.path.join(temp_dir, f"stego_output_{width}x{height}.png")

        start_time = time.time()
        success = perform_encode(image_path, file_path, output_path, password, compress=True)
        end_time = time.time()
        
        if success:
            encode_time = end_time - start_time
            encode_times.append(encode_time)
            print(f"Image size: {width}x{height}, Encode time: {encode_time:.4f} seconds")
        else:
            print(f"Encoding failed for image size: {width}x{height}")
            encode_times.append(None)

    report_path = os.path.join(temp_dir, "image_size_performance.png")

    valid_sizes = [(w*h)/1_000_000 for (w, h), time in zip(image_sizes, encode_times) if time is not None]
    valid_times = [time for time in encode_times if time is not None]
    
    if valid_sizes and valid_times:
        plt.figure(figsize=(10, 6))
        plt.plot(valid_sizes, valid_times, marker='o')
        plt.title('StegX Encoding Performance vs Image Size')
        plt.xlabel('Image Size (Megapixels)')
        plt.ylabel('Encoding Time (seconds)')
        plt.grid(True)
        plt.savefig(report_path)
        print(f"Performance report saved to: {report_path}")

@pytest.mark.performance
def test_decode_performance(temp_dir, create_test_file, create_test_image):

    image_path = create_test_image(temp_dir, 1000, 1000)

    file_sizes = [10, 50, 100, 200]
    decode_times = []
    
    password = "StegXTestPassword123!@#"
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    for size in file_sizes:
        file_path = create_test_file(temp_dir, size)
        stego_path = os.path.join(temp_dir, f"stego_output_{size}kb.png")


        success = perform_encode(image_path, file_path, stego_path, password, compress=True)
        
        if success:
            start_time = time.time()
            success = perform_decode(stego_path, extract_dir, password)
            end_time = time.time()
            
            if success:
                decode_time = end_time - start_time
                decode_times.append(decode_time)
                print(f"File size: {size} KB, Decode time: {decode_time:.4f} seconds")
            else:
                print(f"Decoding failed for file size: {size} KB")
                decode_times.append(None)
        else:
            print(f"Encoding failed for file size: {size} KB, skipping decode test")
            decode_times.append(None)

    report_path = os.path.join(temp_dir, "decode_performance.png")

    valid_sizes = [size for size, time in zip(file_sizes, decode_times) if time is not None]
    valid_times = [time for time in decode_times if time is not None]
    
    if valid_sizes and valid_times:
        plt.figure(figsize=(10, 6))
        plt.plot(valid_sizes, valid_times, marker='o')
        plt.title('StegX Decoding Performance vs File Size')
        plt.xlabel('File Size (KB)')
        plt.ylabel('Decoding Time (seconds)')
        plt.grid(True)
        plt.savefig(report_path)
        print(f"Performance report saved to: {report_path}")

@pytest.mark.performance
def test_compression_effectiveness(temp_dir, create_test_image):
    image_path = create_test_image(temp_dir, 1000, 1000)

    file_types = {
        "text": "This is a sample text file with repeating content. " * 1000,
        "binary": os.urandom(100 * 1024),
        "zeros": bytes([0] * 100 * 1024),
    }
    
    results = {}
    password = "StegXTestPassword123!@#"
    
    for file_type, content in file_types.items():
        file_path = os.path.join(temp_dir, f"test_{file_type}.bin")
        with open(file_path, "wb") as f:
            if isinstance(content, str):
                f.write(content.encode())
            else:
                f.write(content)
        
        original_size = os.path.getsize(file_path)


        output_path_compressed = os.path.join(temp_dir, f"stego_{file_type}_compressed.png")
        start_time = time.time()
        success_compressed = perform_encode(image_path, file_path, output_path_compressed, password, compress=True)
        compressed_time = time.time() - start_time

        output_path_uncompressed = os.path.join(temp_dir, f"stego_{file_type}_uncompressed.png")
        start_time = time.time()
        success_uncompressed = perform_encode(image_path, file_path, output_path_uncompressed, password, compress=False)
        uncompressed_time = time.time() - start_time
        
        if success_compressed and success_uncompressed:
            compressed_size = os.path.getsize(output_path_compressed)
            uncompressed_size = os.path.getsize(output_path_uncompressed)

            compression_ratio = (uncompressed_size - compressed_size) / uncompressed_size * 100
            time_overhead = (compressed_time - uncompressed_time) / uncompressed_time * 100
            
            results[file_type] = {
                "original_size": original_size,
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "compression_ratio": compression_ratio,
                "compressed_time": compressed_time,
                "uncompressed_time": uncompressed_time,
                "time_overhead": time_overhead
            }
            
            print(f"File type: {file_type}")
            print(f"  Original size: {original_size} bytes")
            print(f"  Compressed stego size: {compressed_size} bytes")
            print(f"  Uncompressed stego size: {uncompressed_size} bytes")
            print(f"  Compression ratio: {compression_ratio:.2f}%")
            print(f"  Time overhead: {time_overhead:.2f}%")
        else:
            print(f"Encoding failed for file type: {file_type}")

    if results:
        report_path = os.path.join(temp_dir, "compression_report.txt")
        with open(report_path, "w") as f:
            f.write("StegX Compression Effectiveness Report\n")
            f.write("=====================================\n\n")
            
            for file_type, data in results.items():
                f.write(f"File Type: {file_type}\n")
                f.write(f"  Original Size: {data['original_size']} bytes\n")
                f.write(f"  Compressed Stego Size: {data['compressed_size']} bytes\n")
                f.write(f"  Uncompressed Stego Size: {data['uncompressed_size']} bytes\n")
                f.write(f"  Compression Ratio: {data['compression_ratio']:.2f}%\n")
                f.write(f"  Compressed Encoding Time: {data['compressed_time']:.4f} seconds\n")
                f.write(f"  Uncompressed Encoding Time: {data['uncompressed_time']:.4f} seconds\n")
                f.write(f"  Time Overhead: {data['time_overhead']:.2f}%\n\n")
        
        print(f"Compression report saved to: {report_path}")


@pytest.mark.performance
def test_memory_usage(temp_dir, create_test_file, create_test_image):
    try:
        import memory_profiler
    except ImportError:
        pytest.skip("memory_profiler package not installed")

    image_path = create_test_image(temp_dir, 1000, 1000)
    file_path = create_test_file(temp_dir, 100)  # 100KB file
    output_path = os.path.join(temp_dir, "stego_memory_test.png")
    extract_dir = os.path.join(temp_dir, "extracted_memory")
    os.makedirs(extract_dir, exist_ok=True)
    
    password = "StegXTestPassword123!@#"


    def encode_func():
        perform_encode(image_path, file_path, output_path, password, compress=True)
    
    def decode_func():
        perform_decode(output_path, extract_dir, password)

    print("Profiling memory usage for encoding...")
    encode_mem_usage = memory_profiler.memory_usage((encode_func,), interval=0.1, timeout=60)
    
    print("Profiling memory usage for decoding...")
    decode_mem_usage = memory_profiler.memory_usage((decode_func,), interval=0.1, timeout=60)

    encode_max_mem = max(encode_mem_usage) - encode_mem_usage[0]
    decode_max_mem = max(decode_mem_usage) - decode_mem_usage[0]
    
    print(f"Maximum memory usage during encoding: {encode_max_mem:.2f} MiB")
    print(f"Maximum memory usage during decoding: {decode_max_mem:.2f} MiB")


    report_path = os.path.join(temp_dir, "memory_usage.png")
    # i will try *** later
    plt.figure(figsize=(10, 6))
    plt.plot(encode_mem_usage, label='Encoding')
    plt.plot(decode_mem_usage, label='Decoding')
    plt.title('StegX Memory Usage')
    plt.xlabel('Time (0.1s intervals)')
    plt.ylabel('Memory Usage (MiB)')
    plt.legend()
    plt.grid(True)
    plt.savefig(report_path)
    print(f"Memory usage report saved to: {report_path}")


if __name__ == "__main__":
    pytest.main(["-v", __file__])
