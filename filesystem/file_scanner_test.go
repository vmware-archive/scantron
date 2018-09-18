package filesystem_test

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/pivotal-cf/scantron"
	"github.com/pivotal-cf/scantron/filesystem"
	"github.com/pivotal-cf/scantron/scanlog"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type fakeFileInfo struct {
}

func (f *fakeFileInfo) Name() string {
	return "fake"
}
func (f *fakeFileInfo) Size() int64 {
	return 123
}
func (f *fakeFileInfo) Mode() os.FileMode {
	return 0755
}
func (f *fakeFileInfo) ModTime() time.Time {
	loc, _ := time.LoadLocation("UTC")
	return time.Date(2018, time.August, 3, 5, 2, 5, 2, loc)
}
func (f *fakeFileInfo) IsDir() bool {
	return false
}
func (f *fakeFileInfo) Sys() interface{} {
	return nil
}

var _ = Describe("FileScanner", func() {
	var (
		mockCtrl         *gomock.Controller
		subject          *filesystem.FileScanner
		mockFileMetadata *filesystem.MockFileMetadata
		mockFileWalker   *filesystem.MockFileWalker
	)

	BeforeEach(func() {

		mockCtrl = gomock.NewController(GinkgoT())
		mockFileMetadata = filesystem.NewMockFileMetadata(mockCtrl)
		mockFileWalker = filesystem.NewMockFileWalker(mockCtrl)
		subject = &filesystem.FileScanner{
			Walker:   mockFileWalker,
			Metadata: mockFileMetadata,
			Logger:   scanlog.NewNopLogger(),
		}

	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	It("aborts if walk fails", func() {
		mockFileWalker.EXPECT().Walk().Return(nil, errors.New("an error")).Times(1)

		_, err := subject.ScanFiles()

		Expect(err).To(HaveOccurred())
	})

	It("returns files with metadata", func() {
		info := &fakeFileInfo{}
		path := "some/path/fake"
		mockFileWalker.EXPECT().Walk().Return([]filesystem.WalkedFile{
			{
				Path: path,
				Info: info,
			},
		}, nil).Times(1)
		mockFileMetadata.EXPECT().GetUser(path, info).Return("user", nil).Times(1)
		mockFileMetadata.EXPECT().GetGroup(path, info).Return("group", nil).Times(1)

		files, err := subject.ScanFiles()

		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(ConsistOf(scantron.File{
			Path: path,
			Permissions: info.Mode(),
			Size: info.Size(),
			User: "user",
			Group: "group",
			ModifiedTime: info.ModTime(),
			RegexMatches: nil,
		}))
	})

	It("does assign regexes to files that do match path and content", func() {
		info := &fakeFileInfo{}
		path := "some/valuable/fake"

		mockFileWalker.EXPECT().Walk().Return([]filesystem.WalkedFile{
			{
				Path: path,
				Info: info,
				RegexMatches: []scantron.RegexMatch{
				  {
				    ContentRegex:"content",
				    PathRegex:"path",
          },
        },
			},
		}, nil).Times(1)
		mockFileMetadata.EXPECT().GetUser(path, info).Return("user", nil).Times(1)
		mockFileMetadata.EXPECT().GetGroup(path, info).Return("group", nil).Times(1)

		files, err := subject.ScanFiles()

		Expect(err).NotTo(HaveOccurred())

		Expect(files).To(ConsistOf(scantron.File{
			Path: path,
			Permissions: info.Mode(),
			Size: info.Size(),
			User: "user",
			Group: "group",
			ModifiedTime: info.ModTime(),
			RegexMatches: []scantron.RegexMatch{
        {
          ContentRegex:"content",
          PathRegex:"path",
        },
      },
		}))
	})
})
