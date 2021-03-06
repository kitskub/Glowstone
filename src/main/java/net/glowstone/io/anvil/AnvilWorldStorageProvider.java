package net.glowstone.io.anvil;

import net.glowstone.GlowWorld;
import net.glowstone.io.ChunkIoService;
import net.glowstone.io.WorldMetadataService;
import net.glowstone.io.WorldStorageProvider;
import net.glowstone.io.nbt.NbtWorldMetadataService;

import java.io.File;

/**
 * A {@link WorldStorageProvider} for the Anvil map format.
 */
public class AnvilWorldStorageProvider implements WorldStorageProvider {

    private final File dir;
    private GlowWorld world;
    private AnvilChunkIoService service;
    private NbtWorldMetadataService meta;

    public AnvilWorldStorageProvider(File dir) {
        this.dir = dir;
    }

    public void setWorld(GlowWorld world) {
        if (this.world != null)
            throw new IllegalArgumentException("World is already set");
        this.world = world;
        service = new AnvilChunkIoService(dir);
        meta = new NbtWorldMetadataService(world, dir);
    }

    public ChunkIoService getChunkIoService() {
        return service;
    }

    public WorldMetadataService getMetadataService() {
        return meta;
    }

    public File getFolder() {
        return dir;
    }
}
