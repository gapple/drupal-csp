<?php

namespace Drupal\Tests\csp\Unit;

use Drupal\Core\Asset\LibraryDiscovery;
use Drupal\Core\Cache\MemoryBackend;
use Drupal\Core\Extension\ModuleHandler;
use Drupal\Core\Theme\ActiveTheme;
use Drupal\Core\Theme\ThemeManager;
use Drupal\csp\LibraryPolicyBuilder;
use Drupal\Tests\UnitTestCase;

/**
 * @coversDefaultClass Drupal\csp\LibraryPolicyBuilder
 * @group csp
 */
class LibraryPolicyBuilderTest extends UnitTestCase {

  /**
   * Memory Cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cache;

  /**
   * Mock Module Handler.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $moduleHandler;

  /**
   * Mock Active Theme.
   *
   * @var \Drupal\Core\Theme\ActiveTheme|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $activeTheme;

  /**
   * Mock Theme Manager.
   *
   * @var \Drupal\Core\Theme\ThemeManagerInterface|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $themeManager;

  /**
   * Mock Library Discovery.
   *
   * @var \Drupal\Core\Asset\LibraryDiscoveryInterface|\PHPUnit_Framework_MockObject_MockObject
   */
  protected $libraryDiscovery;

  /**
   * {@inheritdoc}
   */
  public function setUp() {
    parent::setUp();

    $this->cache = new MemoryBackend();

    $this->moduleHandler = $this->getMockBuilder(ModuleHandler::class)
      ->disableOriginalConstructor()
      ->getMock();

    $this->activeTheme = $this->getMockBuilder(ActiveTheme::class)
      ->disableOriginalConstructor()
      ->getMock();
    $this->activeTheme->expects($this->any())
      ->method('getName')
      ->willReturn('stark');
    $this->themeManager = $this->getMockBuilder(ThemeManager::class)
      ->disableOriginalConstructor()
      ->getMock();
    $this->themeManager->expects($this->any())
      ->method('getActiveTheme')
      ->willReturn($this->activeTheme);

    $this->libraryDiscovery = $this->getMockBuilder(LibraryDiscovery::class)
      ->disableOriginalConstructor()
      ->getMock();
  }

  /**
   * Test an empty extension set.
   *
   * @covers ::getSourcesForActiveTheme
   * @covers ::getExtensionSources
   * @covers ::getLibrarySources
   */
  public function testEmptyPolicy() {
    $this->moduleHandler->expects($this->any())
      ->method('getModuleList')
      ->willReturn([]);

    // PHPUnit doesn't allow asserting that a single method is called with each
    // of a set of parameters.
    $this->libraryDiscovery->expects($this->atLeast(2))
      ->method('getLibrariesByExtension')
      ->with($this->logicalOr('stark', 'core'))
      ->willReturn([]);

    $libraryPolicy = new LibraryPolicyBuilder($this->cache, $this->moduleHandler, $this->themeManager, $this->libraryDiscovery);

    $this->assertArrayEquals(
      [
        'script-src' => [],
        'style-src' => [],
      ],
      $libraryPolicy->getSourcesForActiveTheme()
    );
  }

  /**
   * Test that a library's external sources are discovered.
   *
   * @covers ::getSourcesForActiveTheme
   * @covers ::getExtensionSources
   * @covers ::getLibrarySources
   * @covers ::getHostFromUri
   */
  public function testLibraryWithSources() {

    $this->moduleHandler->expects($this->any())
      ->method('getModuleList')
      ->willReturn([]);

    $extensionMap = [
      ['core', []],
      ['stark', ['test' => []]],
    ];
    $this->libraryDiscovery->expects($this->any())
      ->method('getLibrariesByExtension')
      ->willReturnMap($extensionMap);

    // Test a few behaviours:
    // - local files are ignored.
    // - script domains are sorted.
    // - duplicate style domains are filtered.
    $libraryInfo = [
      'js' => [
        [
          'type' => 'file',
          'data' => 'js/script.js',
        ],
        [
          'type' => 'external',
          'data' => 'http://js.example.org/js/script.js',
        ],
        [
          'type' => 'external',
          'data' => 'http://js.example.com/js/script.js',
        ],
      ],
      'css' => [
        [
          'type' => 'external',
          'data' => 'http://css.example.com/css/style1.css',
        ],
        [
          'type' => 'external',
          'data' => 'http://css.example.com/css/style2.css',
        ],
      ],
    ];
    $this->libraryDiscovery->expects($this->atLeastOnce())
      ->method('getLibraryByName')
      ->with('stark', 'test')
      ->willReturn($libraryInfo);

    $libraryPolicy = new LibraryPolicyBuilder($this->cache, $this->moduleHandler, $this->themeManager, $this->libraryDiscovery);

    $this->assertArrayEquals(
      [
        'script-src' => ['js.example.com', 'js.example.org'],
        'style-src' => ['css.example.com'],
      ],
      $libraryPolicy->getSourcesForActiveTheme()
    );
  }

}
