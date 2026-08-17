package com.example;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Random;

/**
 * Example Programm for simple testing of eBPF jAgent.
 */
public class Main {
    private static final int ALLOCATION_SIZE = 10 * 1024 * 1024;
    private static final long INTERVAL_MS = 5_000L;
    private static final String FETCH_URL = "http://example.com";

    public static void main(String[] args) {
        System.out.println(ProcessHandle.current().pid());
        System.out.println("Starting work loop (every " + (INTERVAL_MS/1000) + " s)...");
        while (true) {
            long start = System.currentTimeMillis();
            try {
                doWork();
            } catch (Exception e) {
                System.err.println("Work failed: " + e);
                e.printStackTrace();
            }
            long elapsed = System.currentTimeMillis() - start;
            long sleep = INTERVAL_MS - elapsed;
            if (sleep > 0) {
                try {
                    Thread.sleep(sleep);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    private static void doWork() throws IOException {
        System.out.println("=== iteration at " + System.currentTimeMillis() + " ===");

        byte[] buffer = new byte[ALLOCATION_SIZE];
        new Random().nextBytes(buffer);
        System.out.println("Allocated " + ALLOCATION_SIZE + " bytes");

        byte[] fetched = fetchUrl(FETCH_URL);
        System.out.println("Fetched " + fetched.length + " bytes from " + FETCH_URL);

        File temp = File.createTempFile("fetch-", ".tmp");
        try (FileOutputStream fos = new FileOutputStream(temp)) {
            fos.write(fetched);
        }
        System.out.println("Wrote to temp file: " + temp.getAbsolutePath());

        if (temp.delete()) {
            System.out.println("Deleted temp file");
        } else {
            System.err.println("Failed to delete temp file");
        }
    }

    private static byte[] fetchUrl(String urlStr) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection)url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5_000);
        conn.setReadTimeout(5_000);

        try (InputStream in = conn.getInputStream();
             ByteArrayOutputStream bout = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[4 * 1024];
            int read;
            while ((read = in.read(chunk)) != -1) {
                bout.write(chunk, 0, read);
            }
            return bout.toByteArray();
        } finally {
            conn.disconnect();
        }
    }
}
